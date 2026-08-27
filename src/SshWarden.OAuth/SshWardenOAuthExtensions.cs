using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using SshWarden.Auth;
using SshWarden.Configuration;
using SshWarden.Mcp;

namespace SshWarden.OAuth;

/// <summary>Wires SshWarden to any OAuth 2.1 authorization server.</summary>
/// <remarks>
/// <para>
/// Three calls, in the order a request meets them: the services, the bearer gate, the metadata
/// document. A deployment on static tokens calls none of them.
/// </para>
/// <para>
/// <strong>Nothing here decides which tool runs.</strong> One MCP endpoint carries all seven tools,
/// so a scope required at the route is the intersection of what they all need - and requiring one
/// there also stops the client from <em>asking</em> for more, because a 401 naming a scope is what a
/// client reads to know what to request. The per-tool decision stays in the grant table and the
/// gate; this only establishes who is calling.
/// </para>
/// </remarks>
public static class SshWardenOAuthExtensions
{
    /// <summary>Registers the bearer handler and the authenticator that reads its principal.</summary>
    /// <param name="services">The container.</param>
    /// <param name="configuration">The loaded configuration.</param>
    /// <returns><paramref name="services" />, for chaining.</returns>
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    /// <exception cref="InvalidOperationException">The configuration is not in OAuth mode.</exception>
    /// <remarks>
    /// Before <c>AddSshWarden</c>, like every other seam here: those registrations are
    /// <c>TryAdd</c>, so one made first wins and one made after silently does nothing.
    /// </remarks>
    public static IServiceCollection AddSshWardenOAuth(
        this IServiceCollection services,
        SshWardenConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var oauth = configuration.Auth.OAuth
            ?? throw new InvalidOperationException(
                "AddSshWardenOAuth was called for a configuration with no [auth.oauth] table. The "
                    + "loader refuses that combination, so reaching here means this was called for "
                    + "a deployment that is not in OAuth mode.");

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = oauth.Issuer;

                // The audience is the resource identifier, which is RFC 8707 working: a token minted
                // for some other resource is refused here rather than accepted because it happens to
                // be signed by an issuer this server trusts. Getting this wrong is a 401 that reads
                // as a credential problem and is a configuration one.
                options.Audience = oauth.Resource;

                // Off only for a development or on-premises authorization server, and the loader
                // warns on every start when it is. Everything else about the handler stays at its
                // defaults, which are the framework's and are what a reader expects.
                options.RequireHttpsMetadata = !oauth.AllowPrivateIssuer;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = oauth.Issuer,
                    ValidateAudience = true,
                    ValidAudience = oauth.Resource,
                    ValidateLifetime = true,

                    // No skew. The default is five minutes, which is five minutes in which a revoked
                    // or expired token still runs commands on a production host - and the clocks
                    // involved are a server and an authorization server, both of which run NTP.
                    ClockSkew = TimeSpan.Zero,

                    // Left as the claim they arrive as. The framework's default map rewrites `sub`
                    // into a long URI, and the audit record's whole point is that the value in it is
                    // the value the authorization server sent.
                    NameClaimType = "sub",
                };
            });

        services.AddAuthorization();
        services.TryAddSingleton(oauth);
        services.TryAddSingleton<ISshWardenAuthenticator>(_ => new OAuthAuthenticator(oauth));
        services.TryAddSingleton(ProtectedResourceMetadata.For(oauth));

        // The challenge, and it has to be registered here rather than left to the middleware: the
        // middleware answers "is there a caller" for every mode and must not know how any of them
        // authenticates.
        //
        // **Without this the discovery chain has no first link.** This server publishes a correct
        // RFC 9728 document at both well-known forms and, until 0.4.0, refused every request with a
        // bare `Bearer` - so a client meeting it for the first time was told it needed a credential
        // and never told where to get one. §5.1 of the same RFC is what closes that loop, and the
        // document being right is exactly what makes the omission invisible from inside: every
        // unit test passes, the document is served, and no client can find it.
        services.TryAddSingleton(new BearerChallengeParameters
        {
            ResourceMetadata = ResourceMetadataUrl.UrlFor(oauth.Resource),

            // The configured list, whole. Not the endpoint's, not an intersection - see the type's
            // own remarks, and docs/DESIGN.md §6.5.0 for what narrowing it cost somebody.
            ScopesSupported = oauth.ScopesSupported,
        });

        // A resource server that starts with no signing keys answers 401 to every caller holding a
        // perfectly good token, and that presents as a credential problem rather than as the startup
        // ordering problem it is. The bearer handler fetches lazily, on the first request, so
        // without this the first caller is the one who finds out.
        services.AddHostedService<SigningKeyWarmup>();

        return services;
    }

    /// <summary>Puts the bearer gate in front of the MCP endpoint.</summary>
    /// <param name="app">The application.</param>
    /// <returns><paramref name="app" />, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="app" /> is null.</exception>
    /// <remarks>
    /// <strong>After <c>UseRouting</c> and before <c>UseSshWardenAuthentication</c>, and neither
    /// half is arbitrary.</strong> Before routing there is no endpoint yet, so the gate cannot see
    /// which routes said they need no credential. And SshWarden's own middleware reads the principal
    /// this one establishes, so running it first hands it a request nothing has authenticated.
    /// </remarks>
    public static IApplicationBuilder UseSshWardenOAuth(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseAuthentication().UseAuthorization();
    }

    /// <summary>Maps the RFC 9728 protected-resource metadata document.</summary>
    /// <param name="app">The endpoint route builder.</param>
    /// <exception cref="ArgumentNullException"><paramref name="app" /> is null.</exception>
    /// <remarks>
    /// <para>
    /// Both forms: the root and the one with the resource's path inserted. A conformant client
    /// constructs the second first, so a deployment serving only the root still fails against real
    /// clients.
    /// </para>
    /// <para>
    /// <strong>Marked anonymous in both vocabularies, and finding that out cost a day.</strong> A
    /// host running two authentication middlewares has two words for "this endpoint needs no
    /// credential" - the framework's <c>AllowAnonymous</c> and SshWarden's own
    /// <c>AllowUnauthenticated</c> - and neither reads the other's. Measured on a running server on
    /// 2026-08-26: the document that exists to tell a client where to authenticate answered 401, at
    /// the exact URL this server's own challenges point at, with everything else working.
    /// </para>
    /// </remarks>
    public static void MapSshWardenOAuth(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var document = app.ServiceProvider.GetRequiredService<ProtectedResourceMetadata>();

        foreach (var path in new[]
        {
            ResourceMetadataUrl.Suffix,
            ResourceMetadataUrl.PathFor(document.Resource),
        }.Distinct(StringComparer.Ordinal))
        {
            app.MapGet(path, () => Results.Json(document))
                .WithMetadata(AllowUnauthenticated.Instance)
                .AllowAnonymous();
        }
    }

    /// <summary>Refuses to start until the authorization server's signing keys are in hand.</summary>
    /// <remarks>
    /// A hosted service rather than something the host awaits, so the check cannot be left out by a
    /// deployment that wires the three calls above and forgets a fourth.
    /// </remarks>
    private sealed class SigningKeyWarmup(
        IOptionsMonitor<JwtBearerOptions> options,
        OAuthSection oauth) : IHostedService
    {
        /// <inheritdoc />
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var manager = options.Get(JwtBearerDefaults.AuthenticationScheme).ConfigurationManager;

            if (manager is null)
            {
                // Nothing to warm: a deployment that supplied its own static keys rather than an
                // authority has no discovery document to fetch, and refusing to start would be
                // refusing a configuration that works.
                return;
            }

            OpenIdConnectConfiguration discovered;

            try
            {
                discovered = await manager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception unreachable) when (unreachable is not OperationCanceledException)
            {
                // Shortened. IdentityModel puts several sentences, a retry timestamp and a note
                // about redacted PII on one line, which buries the sentence an operator acts on
                // underneath the sentence this message adds after it. The whole exception is the
                // inner one, for whoever wants the rest.
                throw new AuthorizationServerUnreachableException(
                    Unreachable(oauth, Shortened(unreachable.Message)),
                    unreachable);
            }

            if (discovered.SigningKeys.Count == 0)
            {
                throw new AuthorizationServerUnreachableException(
                    Unreachable(oauth, "its discovery document named no signing keys"));
            }
        }

        /// <inheritdoc />
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        /// <summary>Enough of a library's message to act on, and no more.</summary>
        /// <remarks>
        /// Cut on a word boundary rather than mid-token, because the useful part of these is a URL
        /// and half a URL sends somebody looking for the wrong host. 160 characters fits the
        /// identifier and the reason on a terminal line.
        /// </remarks>
        private static string Shortened(string message)
        {
            const int limit = 160;

            var line = message.ReplaceLineEndings(" ").Trim();

            if (line.Length <= limit)
            {
                return line;
            }

            var cut = line.LastIndexOf(' ', limit);

            // Trailing punctuation trimmed before the ellipsis, so a cut that lands just after a
            // full stop does not read as five dots.
            return string.Concat(line.AsSpan(0, cut < 0 ? limit : cut).TrimEnd(['.', ',', ';', ' ']), "...");
        }

        private static string Unreachable(OAuthSection oauth, string detail) =>
            $"Could not fetch signing keys from {oauth.Issuer}: {detail}. SshWarden will not start "
                + "without them - with no keys it would answer 401 to every caller holding a valid "
                + "token, which reads as a credential problem and is this one. If the authorization "
                + "server is still starting, this clears on a restart"
                + (oauth.AllowPrivateIssuer
                    ? "."
                    : "; if it is on a private address, auth.oauth.allow_private_issuer is what "
                        + "lets this reach it.");
    }
}
