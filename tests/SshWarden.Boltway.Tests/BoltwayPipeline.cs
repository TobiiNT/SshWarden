using System.Text;

using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Http;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SshWarden.Configuration;
using SshWarden.Mcp;
using SshWarden.Testing;

namespace SshWarden.Boltway.Tests;

/// <summary>
/// A running SshWarden pipeline in Boltway mode, in front of an authorization server that answers.
/// </summary>
/// <remarks>
/// <para>
/// Built through the same three extension methods a deployment calls, in the same order, because
/// the defects this exists to catch are ordering defects.
/// </para>
/// <para>
/// <strong>The authorization server is a fake fetcher rather than a listener, and that is the seam
/// working rather than a shortcut.</strong> Boltway requires an https issuer - <c>IssuerString</c>
/// refuses anything else, deliberately - so a loopback listener would mean a certificate this suite
/// would have to make and trust. What it registers instead is an <c>IUpstreamEndpointClient</c>,
/// which <c>AddJwksSigningKeys</c> installs with <c>TryAdd</c>: a registration made before it wins.
/// That is Boltway's documented ordering rule, so exercising it here checks the same thing a
/// deployment relies on when it replaces the transport.
/// </para>
/// <para>
/// Nothing here mints a token. Every assertion the contract makes is about a refusal or about the
/// metadata document, and the key set exists only so the process starts.
/// </para>
/// </remarks>
internal sealed class BoltwayPipeline : IAsyncDisposable
{
    public const string McpPath = "/mcp";

    /// <summary>The issuer. https, because Boltway will not accept anything else.</summary>
    /// <remarks>RFC 2606 reserves <c>.example</c>, so this resolves for nobody.</remarks>
    public const string Issuer = "https://authorization.example";

    /// <summary>The resource identifier, with a path on purpose.</summary>
    /// <remarks>
    /// RFC 9728 §3.1 inserts the well-known suffix between the authority and the path, and an
    /// identifier with no path makes the two forms one URL - which would leave the assertion about
    /// them agreeing with nothing to compare.
    /// </remarks>
    public const string Resource = "https://sshwarden.example/mcp";

    public static readonly string[] Scopes = ["ssh", "ssh.read"];

    private readonly IHost _host;
    private readonly TestSigningKey _key;
    private readonly string _directory;

    private BoltwayPipeline(IHost host, TestSigningKey key, string directory)
    {
        _host = host;
        _key = key;
        _directory = directory;
        Client = host.GetTestClient();
    }

    /// <summary>A client bound to the SshWarden pipeline.</summary>
    public HttpClient Client { get; }

    /// <summary>Starts the pipeline.</summary>
    public static async Task<BoltwayPipeline> StartAsync()
    {
        var key = new TestSigningKey();

        var directory = Path.Combine(Path.GetTempPath(), "sshwarden-boltway", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        var configuration = new SshWardenConfiguration
        {
            Server = new ServerSection { McpPath = McpPath },
            Auth = new AuthSection
            {
                Mode = AuthModes.OAuth,
                OAuth = new OAuthSection
                {
                    Issuer = Issuer,
                    Resource = Resource,
                    ScopesSupported = Scopes,
                },
            },
            Audit = new AuditSection { Path = Path.Combine(directory, "audit.jsonl") },
            Jobs = new JobsSection { Registry = Path.Combine(directory, "jobs.jsonl") },
            Metrics = new MetricsSection(),
        };

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        // Before AddSshWardenBoltway, so this wins the TryAdd inside AddJwksSigningKeys. After it,
        // this registration would compile, run, and do nothing at all - which is the failure mode
        // every seam in both repositories shares.
        builder.Services.AddSingleton<IUpstreamEndpointClient>(new StubAuthorizationServer(key));

        builder.Services.AddSshWardenBoltway(configuration);
        builder.Services.AddSshWarden(configuration);

        var app = builder.Build();

        app.UseRouting();
        app.UseSshWardenBoltway();
        app.UseSshWardenAuthentication();

        app.MapSshWardenBoltway();
        app.MapSshWardenHealth();
        app.MapSshWarden(configuration);

        await app.StartAsync();

        return new BoltwayPipeline(app, key, directory);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();

        await _host.StopAsync();
        _host.Dispose();

        _key.Dispose();

        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A temporary directory outliving one test run is untidy, not broken.
        }
    }

    /// <summary>An authorization server that answers the two documents and nothing else.</summary>
    /// <remarks>
    /// Dispatched on <c>FetchPurpose</c> rather than on the URL. The purpose is what the caller
    /// says it wants and is checked by the type system; matching URLs would make this fixture agree
    /// with one particular spelling of a path that the source under test is free to change.
    /// </remarks>
    private sealed class StubAuthorizationServer(TestSigningKey key) : IUpstreamEndpointClient
    {
        public Task<FetchOutcome> GetAsync(
            UpstreamDocumentRequest request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);

            var body = request.Purpose switch
            {
                FetchPurpose.AuthorizationServerDiscovery =>
                    TestSigningKey.Discovery(Issuer, Issuer + "/jwks"),
                FetchPurpose.AuthorizationServerJwks => key.Jwks(),

                // Named rather than answered with an empty body. A fixture that returns something
                // for a request it was never taught about is a fixture that passes a test measuring
                // nothing.
                _ => null,
            };

            // 404 rather than a Blocked reason, because that is what it is: this fixture serves two
            // documents and the caller asked for a third. Reaching for a block reason would tell the
            // code under test something about an address, which is a claim this fixture is in no
            // position to make.
            if (body is null)
            {
                return Task.FromResult<FetchOutcome>(new FetchOutcome.NotOk(404));
            }

            _ = MediaType.TryParse("application/json", out var json);

            return Task.FromResult<FetchOutcome>(
                new FetchOutcome.Ok(Encoding.UTF8.GetBytes(body), json, null, null));
        }

        public Task<FetchOutcome> PostFormAsync(
            UpstreamFormRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException(
                "Nothing in this pipeline posts a form upstream. If something starts to, this "
                    + "fixture has to be taught what the answer is rather than given a default.");
    }
}
