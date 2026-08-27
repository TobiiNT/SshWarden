using System.Diagnostics;
using System.Text;

using SshWarden.Configuration;

namespace SshWarden.Ssh;

/// <summary>Runs one command on one host, over a pooled connection.</summary>
public sealed class SshCommandRunner
{
    private readonly SshConnectionPool _pool;

    /// <summary>The pool this runner draws from.</summary>
    /// <remarks>
    /// Exposed for the background sweeper, which needs to know which hosts already have a
    /// connection before deciding whether to sweep them at all.
    /// </remarks>
    public SshConnectionPool Pool => _pool;

    /// <summary>Builds the runner.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="pool" /> is null.</exception>
    public SshCommandRunner(SshConnectionPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        _pool = pool;
    }

    /// <summary>Runs a command only if the host already has a live connection.</summary>
    /// <param name="host">The target.</param>
    /// <param name="sshUser">The unix account.</param>
    /// <param name="command">The command line, already built.</param>
    /// <param name="timeoutSeconds">How long the remote side should allow it.</param>
    /// <param name="cancellationToken">Cancels waiting.</param>
    /// <returns>The outcome, or <see langword="null" /> if nothing was connected.</returns>
    /// <exception cref="ArgumentNullException">Any required argument is null.</exception>
    /// <remarks>
    /// For work that is worth doing while somebody is already there and not worth opening a
    /// connection for. Returning null rather than connecting is the whole point: a caller that
    /// wanted a connection would have asked for one.
    /// </remarks>
    public async Task<CommandOutcome?> TryRunOnLiveAsync(
        HostEntry host,
        string sshUser,
        string command,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(sshUser);
        ArgumentException.ThrowIfNullOrWhiteSpace(command);

        var client = _pool.TryGetLive(host.Name, sshUser);
        if (client is null)
        {
            return null;
        }

        var stopwatch = Stopwatch.StartNew();

        using var remote = client.CreateCommand(
            RemoteCommand.Build(command, workdir: null, environment: null, timeoutSeconds));

        remote.CommandTimeout = TimeSpan.FromSeconds(timeoutSeconds + 15);

        await remote.ExecuteAsync(cancellationToken).ConfigureAwait(false);
        stopwatch.Stop();

        var stdout = remote.Result;

        return new CommandOutcome
        {
            CommandLine = remote.CommandText,
            ExitCode = remote.ExitStatus,
            Stdout = stdout,
            Stderr = remote.Error,
            StdoutBytes = Encoding.UTF8.GetByteCount(stdout),
            DurationMs = stopwatch.ElapsedMilliseconds,
        };
    }

    /// <summary>Runs <paramref name="command" /> and waits for it.</summary>
    /// <param name="host">The target.</param>
    /// <param name="sshUser">The unix account, from the grant that allowed the call.</param>
    /// <param name="command">The caller's command, passed through unchanged.</param>
    /// <param name="workdir">Where to run it, or null for the account's login directory.</param>
    /// <param name="environment">Variables to set, or null.</param>
    /// <param name="timeoutSeconds">How long the remote side should allow it.</param>
    /// <param name="cancellationToken">Cancels waiting - see the remarks.</param>
    /// <exception cref="ArgumentNullException">Any required argument is null.</exception>
    /// <remarks>
    /// <para>
    /// Cancelling this stops SshWarden waiting. It does <strong>not</strong> reliably stop the
    /// process on the other end: the library's own documentation says that when a server does not
    /// implement signals it may send no response, so a cancelled command can complete here while it
    /// keeps running there. That is why the timeout is built into the command line instead - the
    /// remote side enforces it, and the exit status says so.
    /// </para>
    /// </remarks>
    public async Task<CommandOutcome> RunAsync(
        HostEntry host,
        string sshUser,
        string command,
        string? workdir,
        IReadOnlyDictionary<string, string>? environment,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(sshUser);
        ArgumentException.ThrowIfNullOrWhiteSpace(command);

        var commandLine = RemoteCommand.Build(command, workdir, environment, timeoutSeconds);
        var client = await _pool.AcquireAsync(host, sshUser, cancellationToken).ConfigureAwait(false);

        var stopwatch = Stopwatch.StartNew();

        // A new channel for this command and nothing else. The connection is reused; nothing about
        // the previous command's shell is.
        using var remote = client.CreateCommand(commandLine);

        // Set above the remote timeout on purpose, so the remote wrapper is what fires first. If
        // this fired first the command would be abandoned from here with no exit status, which
        // records a running process as an unknown - the invisible case the wrapper exists to avoid.
        remote.CommandTimeout = TimeSpan.FromSeconds(timeoutSeconds + 15);

        // ExecuteAsync returns a plain Task: it runs the command and the output is read afterwards,
        // off the streams it filled. Reading Result rather than the stream directly keeps this on
        // the well-travelled path; the bounded read the output budget needs arrives with the budget,
        // where it can sit behind redaction rather than in front of it.
        await remote.ExecuteAsync(cancellationToken).ConfigureAwait(false);
        stopwatch.Stop();

        var stdout = remote.Result;

        return new CommandOutcome
        {
            CommandLine = commandLine,
            ExitCode = remote.ExitStatus,
            Stdout = stdout,
            Stderr = remote.Error,
            StdoutBytes = Encoding.UTF8.GetByteCount(stdout),
            DurationMs = stopwatch.ElapsedMilliseconds,
        };
    }
}
