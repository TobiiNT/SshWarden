using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SshWarden.Configuration;
using SshWarden.Mcp;
using SshWarden.Testing;

namespace SshWarden.OAuth.Tests;

/// <summary>
/// A running SshWarden pipeline in OAuth mode, in front of an authorization server that answers.
/// </summary>
/// <remarks>
/// <para>
/// Built through the same three extension methods a deployment calls, in the same order, because
/// the defects this exists to catch are ordering defects: a fixture that assembled the middleware by
/// hand would pass while the methods it stands for were wired wrong.
/// </para>
/// <para>
/// <strong>Two servers, and only one of them is in memory.</strong> The bearer handler fetches the
/// discovery document with its own <c>HttpClient</c>, which will not reach a <c>TestServer</c>
/// without a backchannel handler this assembly deliberately does not expose - so the authorization
/// server is a real listener on loopback. Plain HTTP, which is what <c>allow_private_issuer</c>
/// permits and what the loader warns about on every start; the configuration here is built in code
/// rather than parsed, so the loader's https rule is not in the way.
/// </para>
/// </remarks>
internal sealed class OAuthPipeline : IAsyncDisposable
{
    public const string McpPath = "/mcp";

    /// <summary>
    /// The resource identifier, with a path on purpose.
    /// </summary>
    /// <remarks>
    /// RFC 9728 §3.1 inserts the well-known suffix between the authority and the path, and an
    /// identifier with no path makes the two forms one URL - which would leave the assertion about
    /// them agreeing with nothing to compare. RFC 2606 reserves <c>.example</c>, so this resolves
    /// for nobody.
    /// </remarks>
    public const string Resource = "https://sshwarden.example/mcp";

    public static readonly string[] Scopes = ["ssh", "ssh.read"];

    private readonly WebApplication _authorizationServer;
    private readonly IHost _host;
    private readonly TestSigningKey _key;
    private readonly string _directory;

    private OAuthPipeline(WebApplication authorizationServer, IHost host, TestSigningKey key, string directory)
    {
        _authorizationServer = authorizationServer;
        _host = host;
        _key = key;
        _directory = directory;
        Client = host.GetTestClient();
    }

    /// <summary>A client bound to the SshWarden pipeline.</summary>
    public HttpClient Client { get; }

    /// <summary>Starts the authorization server, then SshWarden in front of it.</summary>
    public static async Task<OAuthPipeline> StartAsync()
    {
        var key = new TestSigningKey();

        var authorizationServer = WebApplication.CreateSlimBuilder();
        authorizationServer.WebHost.UseUrls("http://127.0.0.1:0");
        authorizationServer.Logging.ClearProviders();

        var server = authorizationServer.Build();

        // Mapped before the server starts and reading the issuer at request time, in that order and
        // not the other one. Port 0 lets the operating system pick - so two of these run at once
        // without waiting for each other's port to be released - but the port is only knowable after
        // StartAsync, and a route mapped after that is a route the server never sees. The first
        // draft of this file did exactly that and every assertion failed at startup, with the
        // discovery fetch reporting a 404 as "unreachable".
        var issuer = string.Empty;

        server.MapGet("/.well-known/openid-configuration", () =>
            Results.Content(TestSigningKey.Discovery(issuer, issuer + "/jwks"), "application/json"));

        server.MapGet("/jwks", () => Results.Content(key.Jwks(), "application/json"));

        await server.StartAsync();

        issuer = server.Urls.First();

        var directory = Path.Combine(Path.GetTempPath(), "sshwarden-oauth", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        var configuration = new SshWardenConfiguration
        {
            Server = new ServerSection { McpPath = McpPath },
            Auth = new AuthSection
            {
                Mode = AuthModes.OAuth,
                OAuth = new OAuthSection
                {
                    Issuer = issuer,
                    Resource = Resource,
                    ScopesSupported = Scopes,

                    // Loopback is a private address, so without this the discovery fetch is refused
                    // before a socket is opened. It is also what turns RequireHttpsMetadata off,
                    // which is what lets the issuer above be http at all.
                    AllowPrivateIssuer = true,
                },
            },
            Audit = new AuditSection { Path = Path.Combine(directory, "audit.jsonl") },
            Jobs = new JobsSection { Registry = Path.Combine(directory, "jobs.jsonl") },
            Metrics = new MetricsSection(),
        };

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        // Before AddSshWarden, because that call's registrations are TryAdd: one made first wins and
        // one made after silently does nothing. The authenticator and the challenge parameters both
        // come from here.
        builder.Services.AddSshWardenOAuth(configuration);
        builder.Services.AddSshWarden(configuration);

        var app = builder.Build();

        app.UseRouting();
        app.UseSshWardenOAuth();
        app.UseSshWardenAuthentication();

        app.MapSshWardenOAuth();
        app.MapSshWardenHealth();
        app.MapSshWarden(configuration);

        await app.StartAsync();

        return new OAuthPipeline(server, app, key, directory);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();

        await _host.StopAsync();
        _host.Dispose();

        await _authorizationServer.StopAsync();
        await _authorizationServer.DisposeAsync();

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
}
