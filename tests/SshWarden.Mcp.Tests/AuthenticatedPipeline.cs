using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Net.Http.Json;
using System.Text.Json;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SshWarden.Authorization;
using SshWarden.Configuration;

namespace SshWarden.Mcp.Tests;

/// <summary>
/// A running SshWarden pipeline over an in-memory server, wired exactly as the host wires it.
/// </summary>
/// <remarks>
/// Built through the same extension methods the deployable calls, in the same order. A fixture that
/// assembled the middleware by hand would pass while the extension methods it is meant to stand for
/// were wired wrong - which is the mistake most worth catching here, because it is the one that
/// leaves a route open.
/// </remarks>
internal sealed class AuthenticatedPipeline : IAsyncDisposable
{
    public const string ValidToken = "0123456789012345678901234567890123456789";
    public const string ReadOnlyToken = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn";
    public const string Subject = "someone";
    public const string ReadOnlySubject = "auditor";
    public const string McpPath = "/mcp";
    public const string AllowedHost = "dev-web-1";
    public const string ForbiddenHost = "prod-web-1";

    private readonly IHost _host;
    private readonly string _directory;

    private AuthenticatedPipeline(IHost host, string directory, string auditPath)
    {
        _host = host;
        _directory = directory;
        AuditPath = auditPath;
        Client = host.GetTestClient();
    }

    public HttpClient Client { get; }

    public string AuditPath { get; }

    /// <summary>Starts the pipeline.</summary>
    /// <param name="policy">A tool policy to register before <c>AddSshWarden</c>, replacing the real one.</param>
    /// <param name="identityFile">
    /// An SSH private key to point <c>[ssh]</c> at instead of the generated one, for the tests about
    /// what happens when it cannot be used.
    /// </param>
    public static async Task<AuthenticatedPipeline> StartAsync(
        ISshWardenToolPolicy? policy = null,
        string? identityFile = null)
    {
        var directory = Path.Combine(Path.GetTempPath(), "sshwarden-mcp", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        var auditPath = Path.Combine(directory, "audit.jsonl");

        var configuration = new SshWardenConfiguration
        {
            Server = new ServerSection { McpPath = McpPath },
            Auth = new AuthSection
            {
                Mode = AuthModes.StaticToken,
                StaticTokens = [
                    new StaticTokenEntry { Name = "laptop", Subject = Subject, Token = ValidToken },
                    new StaticTokenEntry
                    {
                        Name = "audit-laptop",
                        Subject = ReadOnlySubject,
                        Token = ReadOnlyToken,
                    },
                ],
            },

            // Present so the run tool is registered. Nothing here ever connects - the hosts do not
            // resolve - so a call that gets past the gate fails in the SSH layer, which is how these
            // tests tell "allowed" from "refused".
            //
            // The key is real, and generated rather than checked in. It used to be a path to a file
            // that did not exist, which worked only while the pool was built on first use: the
            // startup resolution that turns an unusable key into a startup failure turns that
            // fixture into a fixture that cannot start.
            Ssh = new SshSection { IdentityFile = identityFile ?? WriteGeneratedKey(directory) },
            Hosts = [
                new HostEntry
                {
                    Name = AllowedHost,
                    Fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
                },
                new HostEntry
                {
                    Name = ForbiddenHost,
                    Fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
                },
            ],
            Grants = [
                new Grant
                {
                    Id = "dev-exec",
                    Subject = Subject,
                    Tools = ["run"],
                    Hosts = ["dev-*"],
                    SshUser = "deploy",
                },

                // A subject with a rule that covers no tool this build implements. It stands for the
                // caller who should see an empty tool list rather than a tool that answers "no".
                new Grant
                {
                    Id = "prod-read",
                    Subject = ReadOnlySubject,
                    Tools = ["read_file"],
                    Hosts = [ForbiddenHost],
                    SshUser = "auditor",
                },
            ],
            Audit = new AuditSection { Path = auditPath },
            Jobs = new JobsSection
            {
                Registry = Path.Combine(Path.GetDirectoryName(auditPath)!, "jobs.jsonl"),
            },
            Metrics = new MetricsSection(),
        };

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        // Before AddSshWarden, because its own registrations are TryAdd - so one made first wins
        // and one made after silently does nothing. A test that got that backwards would be
        // exercising the real policy while believing it had replaced it.
        if (policy is not null)
        {
            builder.Services.AddSingleton(policy);
        }

        builder.Services.AddSshWarden(configuration);

        var app = builder.Build();

        app.UseRouting();
        app.UseSshWardenAuthentication();

        app.MapSshWardenHealth();
        app.MapSshWarden(configuration);

        // Two probes, and the pair is the test. One reports the caller the middleware established,
        // which is how the identity is checked without a full MCP exchange. The other is mapped
        // with nothing said about authentication at all - it stands for every route somebody adds
        // later without thinking about it, and it must be closed.
        app.MapGet("/probe/caller", (CallerContext caller) => caller.Require().Subject);
        app.MapGet("/probe/unmarked", () => "reached");

        await app.StartAsync();
        return new AuthenticatedPipeline(app, directory, auditPath);
    }

    /// <summary>Sends one JSON-RPC request over the MCP endpoint and returns the result element.</summary>
    /// <remarks>
    /// Raw JSON-RPC over the transport rather than a client library, so what is exercised is what a
    /// client actually sends - including the event-stream framing, which the transport requires and
    /// which is the reason a per-tool refusal cannot be an HTTP status.
    /// </remarks>
    public async Task<JsonElement> CallAsync(string token, string method, object parameters)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(McpPath, UriKind.Relative))
        {
            Content = JsonContent.Create(new
            {
                jsonrpc = "2.0",
                id = 1,
                method,
                @params = parameters,
            }),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

        using var response = await Client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync(CancellationToken.None);

        foreach (var line in body.Split('\n'))
        {
            if (line.StartsWith("data: ", StringComparison.Ordinal))
            {
                using var document = JsonDocument.Parse(line["data: ".Length..]);
                return document.RootElement.Clone();
            }
        }

        throw new InvalidOperationException("The response carried no event-stream data line: " + body);
    }

    /// <summary>Every audit record written so far.</summary>
    public IReadOnlyList<JsonElement> AuditRecords()
    {
        if (!File.Exists(AuditPath))
        {
            return [];
        }

        return [.. File.ReadAllLines(AuditPath)
            .Where(line => line.Length > 0)
            .Select(line => JsonDocument.Parse(line).RootElement.Clone())];
    }

    /// <summary>Writes a private key nothing has ever authenticated with.</summary>
    /// <remarks>
    /// Generated per fixture and left in a temporary directory, because a key checked into a
    /// repository is a credential in a test fixture whatever it opens - and this one opens nothing.
    /// PKCS#8 PEM: measured on 2026-08-26 that SSH.NET 2026.0.0 parses what
    /// <c>ExportPkcs8PrivateKeyPem</c> writes, which is what lets this avoid shelling out to
    /// <c>ssh-keygen</c> and depending on the machine having it.
    /// </remarks>
    private static string WriteGeneratedKey(string directory)
    {
        var path = Path.Combine(directory, "id_rsa");
        using var key = RSA.Create(2048);
        File.WriteAllText(path, key.ExportPkcs8PrivateKeyPem());

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return path;
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();

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
