using Microsoft.Extensions.DependencyInjection;

using SshWarden.Auth;
using SshWarden.Configuration;

using Xunit;

namespace SshWarden.Mcp.Tests;

/// <summary>
/// That a configured authentication mode has something behind it before the process serves anything.
/// </summary>
/// <remarks>
/// An `oauth` implementation lives in its own assembly - SshWarden.OAuth for any authorization
/// server issuing JWT access tokens, or one a deployment writes - which it references on purpose so
/// a static-token install is not made to carry an authorization server's client libraries. The cost
/// of that separation is that this package cannot register one, so it has to check somebody did.
/// </remarks>
public sealed class AuthModeWiringTests
{
    [Fact]
    public void OAuth_mode_with_nothing_registered_is_a_startup_failure()
    {
        // The alternative is a process that starts, maps the MCP endpoint, and discovers there is no
        // authenticator when the first caller arrives - which is a running server with nothing in
        // front of it for however long that takes.
        var services = new ServiceCollection();

        var problem = Assert.Throws<InvalidOperationException>(
            () => services.AddSshWarden(Configuration(AuthModes.OAuth)));

        // The generic adapter, because it works with any authorization server issuing JWT access
        // tokens - and this message is the one place somebody asking "does it work with mine?" is
        // looking.
        Assert.Contains("AddSshWardenOAuth", problem.Message, StringComparison.Ordinal);

        // And that it says so in as many words, which is the half worth asserting rather than
        // assuming. This message named a specific authorization server for as long as a second
        // adapter shipped for one, and it answered "does it work with mine?" with "no" for every
        // reader who ran something else.
        //
        // **This is the weaker of the two guards available and the trade is deliberate.** Asserting
        // the absence of a particular vendor's name would catch one coming back; it would also put
        // that name in this repository, which is the thing being kept out. Asserting the promise is
        // present catches the message losing it, which is the failure that actually stranded a
        // reader.
        Assert.Contains("any authorization server", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OAuth_mode_with_an_authenticator_registered_first_is_accepted()
    {
        // The control, and it also pins the order: registrations here are TryAdd, so the one made
        // before AddSshWarden wins and one made after silently does nothing.
        var services = new ServiceCollection();
        services.AddSingleton<ISshWardenAuthenticator, StubAuthenticator>();

        services.AddSshWarden(Configuration(AuthModes.OAuth));

        Assert.Contains(services, service => service.ServiceType == typeof(ISshWardenAuthenticator));
    }

    [Fact]
    public void Static_token_mode_registers_its_own_and_needs_nothing_else()
    {
        var services = new ServiceCollection();

        services.AddSshWarden(Configuration(AuthModes.StaticToken));

        Assert.Contains(services, service => service.ServiceType == typeof(ISshWardenAuthenticator));
    }

    private static SshWardenConfiguration Configuration(string mode) => new()
    {
        Server = new ServerSection(),
        Auth = new AuthSection
        {
            Mode = mode,
            StaticTokens = mode == AuthModes.StaticToken
                ? [new StaticTokenEntry
                {
                    Name = "laptop",
                    Subject = "someone",
                    Token = new string('a', 40),
                }]
                : [],
            OAuth = mode == AuthModes.OAuth
                ? new OAuthSection
                {
                    Issuer = "https://auth.example.com",
                    Resource = "https://sshwarden.example.com/mcp",
                }
                : null,
        },
        Audit = new AuditSection { Path = Path.Combine(Path.GetTempPath(), "sshwarden-wiring.jsonl") },
        Jobs = new JobsSection { Registry = Path.Combine(Path.GetTempPath(), "sshwarden-wiring-jobs.jsonl") },
        Metrics = new MetricsSection(),
    };

    private sealed class StubAuthenticator : ISshWardenAuthenticator
    {
        public string Name => "stub";

        public ValueTask<AuthenticationResult> AuthenticateAsync(
            AuthenticationRequest request,
            CancellationToken cancellationToken)
            => ValueTask.FromResult(AuthenticationResult.Refuse("stub", "This authenticator refuses everything."));
    }
}
