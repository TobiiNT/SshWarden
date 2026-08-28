using Xunit;

namespace SshWarden.Ssh.IntegrationTests;

/// <summary>What the idle sweep closes, and what it leaves alone.</summary>
/// <remarks>
/// <para>
/// Against a real server, because the thing being reclaimed is a real connection and "closed" is a
/// claim about a socket rather than about a field.
/// </para>
/// <para>
/// <strong>The cutoff is passed in rather than waited for.</strong> A sweep reading its own idle
/// window can only be reached by letting the timer fire, which means a sleep in the test and a
/// window in production small enough to make one bearable. Handing the decision its input makes
/// every case here exact: a cutoff in the future means everything is idle, one in the past means
/// nothing is.
/// </para>
/// <para>
/// <strong>What these do not cover.</strong> The two races that made the sweep stop removing
/// entries are both a few instructions wide, between a caller reading its entry and that caller
/// reaching the gate. Forcing that interleaving needs a stress loop timed against a sweep or a seam
/// that exists only to be raced, and neither belongs here. What these hold is the contract the sweep
/// keeps, so a later change to it has something to fail.
/// </para>
/// </remarks>
public sealed class ConnectionPoolEvictionTests : IDisposable
{
    private readonly LocalSshServer _server = LocalSshServer.Start();

    public void Dispose() => _server.Dispose();

    [Fact]
    public async Task An_idle_connection_is_closed()
    {
        await using var pool = new SshConnectionPool(_server.Options);

        var client = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);
        Assert.True(client.IsConnected);

        // Everything is idle as of a moment from now, whatever the clock's resolution.
        pool.EvictIdle(DateTimeOffset.UtcNow.AddMinutes(1));

        // The socket, not the bookkeeping. A session on the target's sshd is what the sweep exists
        // to give back.
        //
        // Disposed rather than merely disconnected, which is why this is not `Assert.False` on
        // IsConnected: reading that property on a disposed client throws, and disposal is the
        // stronger claim anyway - a disconnected client still holds its handles.
        _ = Assert.Throws<ObjectDisposedException>(() => _ = client.IsConnected);
        Assert.Null(pool.TryGetLive(_server.AsHostEntry().Name, _server.User));
        Assert.Empty(pool.LiveConnections());
    }

    [Fact]
    public async Task A_connection_used_inside_the_window_is_left_alone()
    {
        // The control. A sweep that closed everything would pass the test above and be useless.
        await using var pool = new SshConnectionPool(_server.Options);

        var client = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);

        pool.EvictIdle(DateTimeOffset.UtcNow.AddMinutes(-1));

        Assert.True(client.IsConnected);
        Assert.NotNull(pool.TryGetLive(_server.AsHostEntry().Name, _server.User));
        Assert.Single(pool.LiveConnections());
    }

    [Fact]
    public async Task A_pair_whose_connection_was_evicted_connects_again()
    {
        // The entry stays in the dictionary with nothing behind it, so the next caller has to be
        // able to tell that from a live connection and reconnect. This is the path a host that goes
        // quiet overnight takes every morning.
        await using var pool = new SshConnectionPool(_server.Options);

        var first = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);
        pool.EvictIdle(DateTimeOffset.UtcNow.AddMinutes(1));
        _ = Assert.Throws<ObjectDisposedException>(() => _ = first.IsConnected);

        var second = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);

        Assert.True(second.IsConnected);
        Assert.NotSame(first, second);
    }

    [Fact]
    public async Task Sweeping_a_pair_that_has_nothing_behind_it_is_harmless()
    {
        // A second sweep over an entry the first already emptied. It reads the gate and the client
        // of an entry that is still there, which is the state that only exists now the entry is
        // kept, so it is worth one pass to say it does nothing rather than throw.
        await using var pool = new SshConnectionPool(_server.Options);

        _ = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);

        pool.EvictIdle(DateTimeOffset.UtcNow.AddMinutes(1));
        pool.EvictIdle(DateTimeOffset.UtcNow.AddMinutes(1));

        var again = await pool.AcquireAsync(_server.AsHostEntry(), _server.User, CancellationToken.None);

        Assert.True(again.IsConnected);
    }
}
