using System.Security.Cryptography;

using Xunit;

namespace SshWarden.Ssh.IntegrationTests;

/// <summary>That an unverified host is not connected to.</summary>
/// <remarks>
/// The one check with no way to turn it off and no trust-on-first-use. Without it, whoever answers
/// on the configured address receives the private key's authority and every command that follows,
/// and the one thing this process is for - that there is a place which knows what ran where - stops
/// being true.
/// </remarks>
public sealed class HostKeyVerificationTests : IDisposable
{
    private readonly LocalSshServer _server = LocalSshServer.Start();

    public void Dispose() => _server.Dispose();

    [Fact]
    public async Task The_configured_fingerprint_lets_the_connection_through()
    {
        // The control. Without it, a pool that refused every host would look like working
        // verification.
        await using var pool = new SshConnectionPool(_server.Options);

        var client = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);

        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task A_fingerprint_for_a_different_key_stops_it()
    {
        // A well-formed fingerprint of some other key - what a caller would present if the machine
        // answering were not the machine the config is about.
        var otherKey = "SHA256:" + Convert.ToBase64String(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("some other host's key"))).TrimEnd('=');

        await using var pool = new SshConnectionPool(_server.Options);

        var failure = await Assert.ThrowsAnyAsync<Exception>(
            () => pool.AcquireAsync(_server.AsHostEntry(otherKey), _server.User, CancellationToken.None));

        // The connection does not happen. Which exception the library raises for a rejected host key
        // is its business and not something to pin; that it does not hand back a usable client is
        // the property.
        Assert.NotNull(failure);
    }

    [Fact]
    public async Task Work_that_may_not_connect_returns_nothing_rather_than_connecting()
    {
        // The rule the background sweeper rests on. A host nobody is working on must cost nothing -
        // no session on its sshd, no directory walk, and no timeline entries that would read as
        // activity. The sweeper also only looks at hosts already listed as live, so this is the
        // second of two guards; it is tested here because it is the one that decides.
        await using var pool = new SshConnectionPool(_server.Options);
        var runner = new SshCommandRunner(pool);

        var outcome = await runner.TryRunOnLiveAsync(
            _server.AsHostEntry(), _server.User, "echo hello", 10, CancellationToken.None);

        Assert.Null(outcome);
        Assert.Empty(pool.LiveConnections());
    }

    [Fact]
    public async Task Work_that_may_not_connect_runs_once_something_else_has_connected()
    {
        // The control. Without it, a method that always returned null would look like a working
        // guard - and change detection would be silently off everywhere.
        await using var pool = new SshConnectionPool(_server.Options);
        var runner = new SshCommandRunner(pool);

        _ = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);

        var outcome = await runner.TryRunOnLiveAsync(
            _server.AsHostEntry(), _server.User, "echo hello", 10, CancellationToken.None);

        Assert.NotNull(outcome);
        Assert.Equal("hello\n", outcome.Stdout);
    }

    [Fact]
    public async Task A_second_call_reuses_the_connection()
    {
        // What the pool is for: the TCP connection and the SSH handshake are paid once. Asserting
        // the same instance rather than timing it, because a timing assertion is a flake and the
        // thing that matters is identity - a second client would be a second session on the far
        // side's count.
        await using var pool = new SshConnectionPool(_server.Options);

        var first = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);
        var second = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);

        Assert.Same(first, second);
    }
}
