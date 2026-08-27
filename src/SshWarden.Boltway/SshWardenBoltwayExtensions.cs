using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Ids;
using Boltway.ResourceServer.Authorization;
using Boltway.ResourceServer.Configuration;
using Boltway.ResourceServer.DependencyInjection;
using Boltway.ResourceServer.Endpoints;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using SshWarden.Auth;
using SshWarden.Configuration;
using SshWarden.Mcp;

namespace SshWarden.Boltway;

/// <summary>Wires SshWarden to an OAuth 2.1 authorization server.</summary>
/// <remarks>
/// <para>
/// Three calls, in the order a request meets them: the services, the bearer gate, the metadata
/// document. A deployment on static tokens calls none of them and does not reference this assembly.
/// </para>
/// <para>
/// <strong>Nothing here decides which tool runs.</strong> One MCP endpoint carries all seven, so a
/// scope required at the route is the intersection of what they all need - and requiring one there
/// also blocks the client from <em>asking</em> for more, because a 401 that names a scope is what a
/// client reads to know what to request. The per-tool decision stays where it was built in step 2,
/// in the grant table and the gate; this only establishes who is calling.
/// </para>
/// </remarks>
public static class SshWardenBoltwayExtensions
{
    /// <summary>Registers the resource server and the authenticator that reads its principal.</summary>
    /// <param name="services">The container.</param>
    /// <param name="configuration">The loaded configuration.</param>
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    /// <exception cref="InvalidOperationException">The configuration is not in OAuth mode.</exception>
    /// <remarks>
    /// <para>
    /// Registered before <c>AddSshWarden</c> or after it makes no difference for the authenticator -
    /// this uses <c>TryAdd</c> like every other seam, so a deployment replacing it registers first
    /// and wins. What is not optional is the order of the two middlewares at
    /// <see cref="UseSshWardenBoltway" />.
    /// </para>
    /// <para>
    /// The signing keys come from a source read fresh per validation rather than a list captured at
    /// startup, so a key rotation is picked up without a restart. That matters more here than it
    /// looks: the authorization server publishes one key and has no rotation scheduler, so the day
    /// somebody rotates by hand is the day every token signed with the new key is refused by any
    /// resource server holding a stale set.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddSshWardenBoltway(
        this IServiceCollection services,
        SshWardenConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var oauth = configuration.Auth.OAuth
            ?? throw new InvalidOperationException(
                "AddSshWardenBoltway was called for a configuration with no [auth.oauth] table. "
                    + "The loader refuses that combination, so reaching here means this was called "
                    + "for a deployment that is not in OAuth mode.");

        // Parsed rather than assumed, and the failure names the configuration key. AddJwksSigningKeys
        // parses it too and throws on a bad one, so this is not the only check - it is the one whose
        // message says `auth.oauth.issuer`, which is what somebody holding the config file needs.
        // The library's own message names the value and not the field, correctly: it has no idea
        // where the value came from.
        if (!IssuerString.TryCreate(oauth.Issuer, out _, out var issuerProblem))
        {
            throw new InvalidOperationException(
                $"auth.oauth.issuer is '{oauth.Issuer}', which is not a usable issuer: {issuerProblem}");
        }

        // Before AddJwksSigningKeys, which registers its own with TryAdd - so this one wins and the
        // library's default is what a deployment gets when it has not asked for anything else. That
        // ordering is Boltway's documented seam rather than a trick, and it is the whole mechanism
        // by which a config file setting reaches a transport the library owns.
        //
        // From the config file and not from a parameter here, so there is one place that decides it.
        // A parameter as well would be a second answer to the same question, and the one that does
        // not appear in the file is the one nobody reviewing the deployment would see.
        services.TryAddSingleton(new UpstreamEndpointClientOptions
        {
            AllowPrivateAddresses = oauth.AllowPrivateIssuer,
        });

        services.AddBoltwayProtectedResource(options =>
        {
            options.Resource = oauth.Resource;
            options.ResourceName = "SshWarden";
            options.AuthorizationServer = oauth.Issuer;

            foreach (var scope in oauth.ScopesSupported)
            {
                options.ScopesSupported.Add(scope);
            }

            // SigningKeySource is deliberately not set here. AddJwksSigningKeys installs it through
            // IConfigureOptions, which runs after this callback and therefore wins - assigning it
            // here as well would be a value that looks authoritative and is overwritten.
        });

        services.TryAddSingleton<ISshWardenAuthenticator, BoltwayAuthenticator>();

        // The challenge SshWarden's own middleware writes. Boltway's middleware challenges first for
        // anything it treats as protected, and its challenge already carries resource_metadata - so
        // what this covers is the narrower case where a token Boltway accepted is refused by
        // BoltwayAuthenticator, on a claim the token does not carry. The client is holding a valid
        // token and has still been refused; the pointer is how it finds out what this resource
        // wanted.
        services.TryAddSingleton(new BearerChallengeParameters
        {
            ResourceMetadata = ResourceMetadataUrl.UrlFor(oauth.Resource),
            ScopesSupported = oauth.ScopesSupported,
        });

        // Registered before AddJwksSigningKeys, and the order is the whole point: hosted services
        // start in registration order, so this one runs first and is the one that reports. What it
        // reports is an AuthorizationServerUnreachableException, which the host translates into one
        // line and exit 69 - the library's own primer throws InvalidOperationException, which would
        // reach the host as an unhandled defect with a stack trace on top of the sentence naming the
        // server that did not answer. The message also names auth.oauth.allow_private_issuer, which
        // a library with no idea what a config file looks like cannot mention.
        //
        // The library's primer still runs, immediately after, and does not fetch again: RefreshAsync
        // returns StillFresh against the snapshot this one just filled, and it logs the key count.
        // A failed fetch never reaches it, because this one has already thrown.
        services.AddHostedService<SigningKeyWarmup>();
        services.AddJwksSigningKeys(oauth.Issuer);

        return services;
    }

    /// <summary>Puts the bearer gate in front of the MCP endpoint.</summary>
    /// <param name="app">The application.</param>
    /// <exception cref="ArgumentNullException"><paramref name="app" /> is null.</exception>
    /// <remarks>
    /// <strong>After <c>UseRouting</c> and before <c>UseSshWardenAuthentication</c>, and neither
    /// half of that is arbitrary.</strong> Before routing there is no endpoint yet, so the gate
    /// cannot see that the metadata document is the one response that must answer without a
    /// credential. And SshWarden's own middleware reads the principal this one establishes, so
    /// running it first would hand it a request nothing had authenticated.
    /// </remarks>
    public static IApplicationBuilder UseSshWardenBoltway(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseBoltwayProtectedResource();
    }

    /// <summary>Maps the RFC 9728 protected-resource metadata document.</summary>
    /// <param name="app">The endpoint route builder.</param>
    /// <exception cref="ArgumentNullException"><paramref name="app" /> is null.</exception>
    /// <remarks>
    /// <para>
    /// Unauthenticated, and it has to be: it is what a client reads to find out where to
    /// authenticate. This is what lets an MCP client discover the flow with nothing configured by
    /// hand, which is the whole reason this mode is worth having over a token in a file.
    /// </para>
    /// <para>
    /// <strong>Saying so takes both vocabularies, and finding that out cost a running server.</strong>
    /// Boltway marks these endpoints <c>AllowAnonymous</c>, which is what its own middleware reads.
    /// SshWarden's middleware reads <see cref="AllowUnauthenticated" />, its own marker, and knows
    /// nothing about the framework's - so the document these two calls exist to publish answered
    /// 401, at the exact URL this server's challenges point a client at. Measured against a running
    /// process on 2026-08-26: both well-known paths, both 401, with the keys fetched and everything
    /// else working.
    /// </para>
    /// <para>
    /// The marker goes on a group rather than on a path, so whatever Boltway maps here is covered
    /// including anything a later version adds - and nothing else is. An endpoint SshWarden did not
    /// mount stays behind the credential even if it marks itself anonymous, which is the direction
    /// to be wrong in.
    /// </para>
    /// </remarks>
    public static void MapSshWardenBoltway(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var metadata = app.MapGroup(string.Empty);
        metadata.MapProtectedResourceMetadata();
        metadata.WithMetadata(AllowUnauthenticated.Instance);
    }

    /// <summary>Refuses to start until the authorization server's signing keys are in hand.</summary>
    /// <remarks>
    /// <para>
    /// A resource server that starts with no keys serves 401 to every caller holding a perfectly
    /// good token, and that presents as an authentication problem rather than as the startup
    /// ordering problem it is. Failing here is the point: the process does not come up, and the
    /// message names the authorization server it could not reach.
    /// </para>
    /// <para>
    /// A hosted service rather than something the host awaits, so the check cannot be left out by a
    /// deployment that wires the three calls and forgets a fourth.
    /// </para>
    /// </remarks>
    private sealed class SigningKeyWarmup(JwksKeySource keys, SshWardenConfiguration configuration)
        : IHostedService
    {
        private readonly OAuthSection oauth = configuration.Auth.OAuth
            ?? throw new InvalidOperationException(
                "The signing-key warmup resolved a configuration with no [auth.oauth] table. "
                    + "AddSshWardenBoltway refuses that combination, so this service cannot be "
                    + "registered without one.");

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var warm = await keys.RefreshAsync(cancellationToken).ConfigureAwait(false);

            // The key count, not the outcome. This used to insist on `Refreshed`, which is true only
            // while this is the first thing to touch the source - and it is, today, because it is
            // registered before AddJwksSigningKeys. But a source somebody else warmed first answers
            // `StillFresh` with a full key set, and refusing to start on that would be refusing a
            // deployment that has exactly what it needs. What this service is for is "are there
            // keys", and that is the question to ask.
            if (warm.KeyCount == 0)
            {
                throw new AuthorizationServerUnreachableException(
                    $"Could not fetch signing keys from {oauth.Issuer}: {warm.Detail}. SshWarden "
                        + "will not start without them - with no keys it would answer 401 to every "
                        + "caller holding a valid token, which reads as a credential problem and is "
                        + "this one. If the authorization server is still starting, this clears on "
                        + "a restart"
                        + (oauth.AllowPrivateIssuer
                            ? "."
                            : "; if it is on a private address, auth.oauth.allow_private_issuer is "
                                + "what lets this reach it."));
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
