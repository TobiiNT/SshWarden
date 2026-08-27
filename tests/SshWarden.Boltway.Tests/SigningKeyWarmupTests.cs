using Boltway.OAuth.Net;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using SshWarden.Auth;
using SshWarden.Configuration;
using SshWarden.Mcp;

using Xunit;

namespace SshWarden.Boltway.Tests;

/// <summary>
/// What this server does when the authorization server does not answer.
/// </summary>
/// <remarks>
/// <para>
/// A resource server that starts with no signing keys answers 401 to every caller holding a
/// perfectly good token, which reads as a credential problem and is a deployment ordering one - so
/// it refuses to start. That much both this repository and the library it now calls agree on.
/// </para>
/// <para>
/// <strong>Which exception carries the refusal is this repository's, and it is load-bearing.</strong>
/// <c>Program</c> catches exactly two types and translates them into one line and an exit code;
/// everything else is a defect and gets a stack trace. <c>AddJwksSigningKeys</c> ships its own
/// primer, which throws <c>InvalidOperationException</c> - correctly, for a library with no idea
/// what a config file looks like - and if that one reached the host first, an operator would get a
/// stack trace on top of the sentence naming the server that did not answer, and exit 134 rather
/// than 69. This asserts the ordering that stops it.
/// </para>
/// </remarks>
public sealed class SigningKeyWarmupTests
{
    [Fact]
    public async Task An_authorization_server_that_does_not_answer_refuses_the_start_by_name()
    {
        await using var app = Build(new SilentAuthorizationServer());

        var refusal = await Assert.ThrowsAsync<AuthorizationServerUnreachableException>(
            () => app.StartAsync());

        // The issuer, so somebody reading one line of stderr knows which host to go and look at.
        Assert.Contains(BoltwayPipeline.Issuer, refusal.Message, StringComparison.Ordinal);

        // And the setting that lets it reach an authorization server on this network, because a
        // loopback issuer refused by the RFC 6890 check produces exactly this failure and the cure
        // is a config key rather than a restart. Named only when it is off - see the sibling.
        Assert.Contains("allow_private_issuer", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_private_address_hint_is_not_offered_to_a_deployment_that_already_set_it()
    {
        // The control. Without it the assertion above passes against a message that names the
        // setting unconditionally - which is advice to turn on something already on, and it is the
        // one sentence in that message an operator would act on.
        await using var app = Build(new SilentAuthorizationServer(), allowPrivateIssuer: true);

        var refusal = await Assert.ThrowsAsync<AuthorizationServerUnreachableException>(
            () => app.StartAsync());

        Assert.DoesNotContain("allow_private_issuer", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_authorization_server_that_answers_starts()
    {
        // The control for both of the above: without it they pass against a server that refuses to
        // start no matter what the authorization server says, which is the same outage with a
        // better message.
        await using var pipeline = await BoltwayPipeline.StartAsync();

        using var response = await pipeline.Client.GetAsync(
            new Uri("/.well-known/oauth-protected-resource/mcp", UriKind.Relative));

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
    }

    private static WebApplication Build(IUpstreamEndpointClient upstream, bool allowPrivateIssuer = false)
    {
        var directory = Path.Combine(Path.GetTempPath(), "sshwarden-warmup", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        var configuration = new SshWardenConfiguration
        {
            Server = new ServerSection { McpPath = BoltwayPipeline.McpPath },
            Auth = new AuthSection
            {
                Mode = AuthModes.OAuth,
                OAuth = new OAuthSection
                {
                    Issuer = BoltwayPipeline.Issuer,
                    Resource = BoltwayPipeline.Resource,
                    AllowPrivateIssuer = allowPrivateIssuer,
                },
            },
            Audit = new AuditSection { Path = Path.Combine(directory, "audit.jsonl") },
            Jobs = new JobsSection { Registry = Path.Combine(directory, "jobs.jsonl") },
            Metrics = new MetricsSection(),
        };

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        builder.Services.AddSingleton(upstream);
        builder.Services.AddSshWardenBoltway(configuration);
        builder.Services.AddSshWarden(configuration);

        return builder.Build();
    }

    /// <summary>An authorization server that is not there.</summary>
    /// <remarks>
    /// A transport failure rather than a 404, because the two are different deployments and this is
    /// the one the message is written for: a 404 means something answered and is not an
    /// authorization server, and nothing answering at all is the ordering problem where the fix is
    /// to wait or to open a route.
    /// </remarks>
    private sealed class SilentAuthorizationServer : IUpstreamEndpointClient
    {
        public Task<FetchOutcome> GetAsync(
            UpstreamDocumentRequest request, CancellationToken cancellationToken) =>
            Task.FromResult<FetchOutcome>(
                new FetchOutcome.TransportFailed("nothing is listening on this address"));

        public Task<FetchOutcome> PostFormAsync(
            UpstreamFormRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException("Nothing in this pipeline posts a form upstream.");
    }
}
