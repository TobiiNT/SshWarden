using System.Collections.Concurrent;

using Renci.SshNet;
using Renci.SshNet.Common;

using SshWarden.Configuration;

namespace SshWarden.Ssh;

/// <summary>Keeps one SSH connection per host and unix account, and hands it out.</summary>
/// <remarks>
/// <para>
/// What is pooled is the <em>connection</em> - the TCP socket and the SSH handshake, which are
/// expensive and carry no state worth hiding. What is <strong>not</strong> pooled is anything
/// shell-shaped: every command opens its own channel, so it inherits no working directory, no
/// environment and no <c>sudo</c> timestamp from the command before it.
/// </para>
/// <para>
/// <strong>The trap at this layer is the shell stream</strong>, and it is worth naming because the
/// library's own community advice points straight at it: opening one and writing several commands
/// into it looks tidier and is faster still. It also keeps exactly the state this project dropped
/// on purpose - and the cost lands on the audit log, where a record would say <c>npm install</c>
/// with no way to know which directory that was, unless the whole session is replayed. The log
/// being readable one line at a time is the reason the project exists.
/// </para>
/// <para>
/// The key is the pair, not the host. Two grants may reach one machine as two different unix
/// accounts, and those are two connections - collapsing them would mean the account a command runs
/// as depends on who connected first.
/// </para>
/// </remarks>
public sealed class SshConnectionPool : IAsyncDisposable
{
    private readonly ConcurrentDictionary<PoolKey, Entry> _entries = new();
    private readonly SshSection _options;
    private readonly PrivateKeyFile _identity;
    private readonly TimeSpan _idleEviction;
    private readonly Timer _sweeper;
    private bool _disposed;

    /// <summary>Builds the pool.</summary>
    /// <param name="options">The <c>[ssh]</c> settings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options" /> is null.</exception>
    public SshConnectionPool(SshSection options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;

        // Read once at startup rather than per connection. A key that has been replaced under a
        // running process should not take effect halfway through a working session without anybody
        // restarting anything - and a key that has been *deleted* should fail loudly here rather
        // than at the first command.
        //
        // Restated as a configuration problem, because that is what it is and because SSH.NET's own
        // message does not say which file. `Invalid private key file.` with a stack trace, printed
        // by a process that has just failed to start, sends an operator looking through the config
        // for a key it never names. MapSshWarden resolves this pool at startup so this is reached
        // there rather than inside the first tool call.
        try
        {
            _identity = new PrivateKeyFile(options.IdentityFile);
        }
        catch (Exception unusable) when (unusable is SshException or IOException or UnauthorizedAccessException)
        {
            throw new SshWardenConfigurationException(options.IdentityFile, [
                $"ssh.identity_file is '{options.IdentityFile}', which this process could not read "
                    + $"as an SSH private key: {unusable.Message} The config loader checks that the "
                    + "file is there and that nobody else can read it; whether the bytes are a key "
                    + "is asked here, and every tool call would fail on it.",
            ]);
        }

        _idleEviction = TimeSpan.FromSeconds(options.IdleEvictionSeconds);

        // Swept on a timer rather than only when the next call happens to arrive. A connection
        // nobody asks for again would otherwise be held forever, and it is not free on the other
        // end: it occupies a session on the target host's sshd, against a limit that host sets.
        _sweeper = new Timer(_ => EvictIdle(), state: null, _idleEviction, _idleEviction);
    }

    /// <summary>Gets a connected client for <paramref name="host" /> as <paramref name="sshUser" />.</summary>
    /// <param name="host">The target, from the config file.</param>
    /// <param name="sshUser">The unix account, from the grant that allowed the call.</param>
    /// <param name="cancellationToken">Cancels the connect.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    /// <exception cref="ObjectDisposedException">The pool has been disposed.</exception>
    /// <remarks>
    /// The client is owned by the pool and must not be disposed by the caller. Commands run on it
    /// concurrently by design: one connection multiplexes channels, and the library's session
    /// semaphore exists for exactly that. The ceiling is the server's
    /// <c>MaxSessions</c> - ten by default on both sides - so a host that needs more concurrency
    /// than that needs more than one connection, not a larger number in this config.
    /// </remarks>
    public async Task<SshClient> AcquireAsync(
        HostEntry host,
        string sshUser,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(sshUser);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var key = new PoolKey(host.Name, sshUser);
        var entry = _entries.GetOrAdd(key, _ => new Entry());

        // One connect at a time per key. Without it, two calls arriving together for a cold host
        // both build a client and one is leaked - still connected, still holding a session on the
        // far side, and no longer referenced by anything that would close it.
        await entry.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Checked rather than assumed. A pooled connection can have died since it was last used -
            // the host rebooted, a firewall dropped the idle flow - and the failure mode of not
            // checking is a command that reports a transport error instead of running.
            if (entry.Client is { IsConnected: true })
            {
                entry.Touch();
                return entry.Client;
            }

            entry.Close();
            entry.Client = await ConnectAsync(host, sshUser, cancellationToken).ConfigureAwait(false);
            entry.Touch();
            return entry.Client;
        }
        finally
        {
            _ = entry.Gate.Release();
        }
    }

    /// <summary>The host and account pairs that currently have a live connection.</summary>
    /// <remarks>
    /// <para>
    /// For the background sweeper, and the reason it exists on the pool rather than being inferred:
    /// a sweep must never <em>open</em> a connection. A host nobody is working on should cost
    /// nothing - no SSH session on its sshd, no directory walk, and no entries on a timeline that
    /// would then look like activity.
    /// </para>
    /// <para>
    /// A snapshot. A connection can die between this returning and the caller using it, which the
    /// caller has to expect anyway.
    /// </para>
    /// </remarks>
    public IReadOnlyList<(string Host, string SshUser)> LiveConnections()
    {
        var live = new List<(string, string)>();

        foreach (var (key, entry) in _entries)
        {
            if (entry.Client is { IsConnected: true })
            {
                live.Add((key.Host, key.SshUser));
            }
        }

        return live;
    }

    /// <summary>The client for a pair, if one is already connected.</summary>
    /// <param name="host">The host name.</param>
    /// <param name="sshUser">The unix account.</param>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    /// <remarks>
    /// Never connects. This is the half of the pool the sweeper is allowed to use.
    /// </remarks>
    public SshClient? TryGetLive(string host, string sshUser)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(sshUser);

        return _entries.TryGetValue(new PoolKey(host, sshUser), out var entry)
            && entry.Client is { IsConnected: true } client
            ? client
            : null;
    }

    /// <summary>Closes every connection.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _sweeper.DisposeAsync().ConfigureAwait(false);

        foreach (var entry in _entries.Values)
        {
            entry.Close();
            entry.Gate.Dispose();
        }

        _entries.Clear();
    }

    private async Task<SshClient> ConnectAsync(
        HostEntry host,
        string sshUser,
        CancellationToken cancellationToken)
    {
        var connectionInfo = new ConnectionInfo(
            host.ResolvedAddress,
            host.Port,
            sshUser,
            new PrivateKeyAuthenticationMethod(sshUser, _identity))
        {
            Timeout = TimeSpan.FromSeconds(_options.ConnectTimeoutSeconds),
        };

        var client = new SshClient(connectionInfo);

        // Host key verification, with no trust-on-first-use and no way to switch it off. Without
        // it, whoever answers on that address receives the private key's authority and every
        // command that follows - and the one thing this process is for is that there is a place
        // which knows what ran where. A connection it could not verify does not know.
        client.HostKeyReceived += (_, keyEvent) => Verify(host, keyEvent);

        try
        {
            await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            client.Dispose();
            throw;
        }

        return client;
    }

    private static void Verify(HostEntry host, HostKeyEventArgs keyEvent)
    {
        // The raw key is hashed here rather than reading the library's formatted fingerprint, so
        // the comparison does not depend on how a dependency chose to render it. A rendering that
        // changes - padding, prefix, algorithm - would otherwise turn a verification into a string
        // mismatch, or worse into a match on something else.
        keyEvent.CanTrust = HostFingerprint.Matches(host.Fingerprint, keyEvent.HostKey);
    }

    private void EvictIdle()
    {
        var cutoff = DateTimeOffset.UtcNow - _idleEviction;

        foreach (var (key, entry) in _entries)
        {
            // Only if the gate is free. An entry mid-connect is not idle, and taking it away from
            // under the call that is building it would close a client that call is about to use.
            if (!entry.Gate.Wait(0))
            {
                continue;
            }

            var evicted = false;

            try
            {
                if (entry.Client is not null && entry.LastUsed < cutoff)
                {
                    entry.Close();
                    _ = _entries.TryRemove(key, out _);
                    entry.Gate.Dispose();
                    evicted = true;
                }
            }
            finally
            {
                // Whether *this* pass disposed *this* gate, rather than whether the dictionary holds
                // anything under this key. Those stop being the same question the moment an
                // AcquireAsync puts a fresh entry there between the removal above and the check: the
                // lookup then finds the new entry, says yes, and releases the old gate that was just
                // disposed. Releasing a disposed semaphore throws, and this runs on a timer thread
                // where an exception is attached to nothing and takes the process with it - which is
                // the outcome the dictionary lookup was reaching for and narrowly missed.
                if (!evicted)
                {
                    _ = entry.Gate.Release();
                }
            }
        }
    }

    private readonly record struct PoolKey(string Host, string SshUser);

    private sealed class Entry
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);

        public SshClient? Client { get; set; }

        public DateTimeOffset LastUsed { get; private set; } = DateTimeOffset.UtcNow;

        public void Touch() => LastUsed = DateTimeOffset.UtcNow;

        public void Close()
        {
            Client?.Dispose();
            Client = null;
        }
    }
}
