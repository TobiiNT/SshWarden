using System.Collections.Concurrent;

using SshWarden.Configuration;
using SshWarden.Ssh;

namespace SshWarden.Changes;

/// <summary>Sweeps the watched paths of every host that already has a connection.</summary>
/// <remarks>
/// <para>
/// <strong>Why a background sweep and not a snapshot around each command.</strong> Snapshotting
/// before and after every <c>run</c> reads as the obvious design and has three holes. Two commands
/// running at once on one host produce nested snapshots, so one command's changes get attributed to
/// the other - and running at once is the normal case here, not an edge. A query like "what changed
/// in the last ten minutes" has nothing to compare against, because the only baselines that exist
/// are the ones taken around commands. And walking a whole directory tree twice per command adds
/// that cost to every command's latency.
/// </para>
/// <para>
/// A periodic sweep answers all three, and costs less: fifty short commands in one interval are one
/// walk rather than a hundred.
/// </para>
/// <para>
/// <strong>What it gives up, and why that is the honest choice.</strong> Exact per-command
/// attribution does not exist when commands overlap. Not "is hard" - does not exist. The two
/// alternatives both pretend otherwise: locking a host to one command at a time buys precision by
/// destroying the concurrency this design is built around, and accepting misattribution reports a
/// guess as an observation. This records what it knows, and how much that is worth, in the same
/// line.
/// </para>
/// <para>
/// It never opens a connection. A host nobody is working on costs nothing - no session on its sshd,
/// no directory walk, and no timeline entries that would read as activity.
/// </para>
/// </remarks>
public sealed class ChangeSweeper : IAsyncDisposable
{
    private readonly SshCommandRunner _runner;
    private readonly HostRegistry _hosts;
    private readonly ChangeTimeline _timeline;
    private readonly WatchSection _options;
    private readonly SweepProblems _problems;
    private readonly ConcurrentDictionary<(string Host, string SshUser), Dictionary<string, FileState>> _seen = new();
    private readonly CancellationTokenSource _stopping = new();
    private readonly Task _loop;

    /// <summary>Starts the sweeper.</summary>
    /// <param name="runner">Used only through its non-connecting entry point.</param>
    /// <param name="hosts">The configured hosts.</param>
    /// <param name="timeline">Where sweeps are recorded.</param>
    /// <param name="options">The <c>[watch]</c> settings.</param>
    /// <param name="problems">Where sweeps that could not run are recorded.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public ChangeSweeper(
        SshCommandRunner runner,
        HostRegistry hosts,
        ChangeTimeline timeline,
        WatchSection options,
        SweepProblems problems)
    {
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentNullException.ThrowIfNull(timeline);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(problems);

        _runner = runner;
        _hosts = hosts;
        _timeline = timeline;
        _options = options;
        _problems = problems;

        _loop = options.Paths.Count == 0
            ? Task.CompletedTask
            : Task.Run(() => LoopAsync(_stopping.Token));
    }

    /// <summary>Runs one round of sweeps, for a test or a caller that wants one now.</summary>
    /// <param name="cancellationToken">Cancels the round.</param>
    /// <returns>How many pairs were swept.</returns>
    public async Task<int> SweepOnceAsync(CancellationToken cancellationToken)
    {
        if (_options.Paths.Count == 0)
        {
            return 0;
        }

        var swept = 0;

        foreach (var (host, sshUser) in _runner.Pool.LiveConnections())
        {
            if (_hosts.Find(host) is not { } target)
            {
                continue;
            }

            if (await SweepAsync(target, sshUser, cancellationToken).ConfigureAwait(false))
            {
                swept++;
            }
        }

        return swept;
    }

    /// <summary>Stops the sweeper.</summary>
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);

        try
        {
            await _loop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The way this loop is meant to end.
        }

        _stopping.Dispose();
    }

    private async Task LoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_options.IntervalSeconds));

        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            try
            {
                _ = await SweepOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception failure)
            {
                // One failing round must not end the loop. A host that becomes unreachable, a
                // connection that dies mid-sweep - these are ordinary, and a sweeper that stops on
                // the first one is a sweeper that is silently off for the rest of the process's
                // life. The reason is kept where a caller can ask for it.
                _problems.Set("*", "*", failure.Message);
            }
        }
    }

    private async Task<bool> SweepAsync(HostEntry target, string sshUser, CancellationToken cancellationToken)
    {
        var key = (target.Name, sshUser);

        var outcome = await _runner.TryRunOnLiveAsync(
            target,
            sshUser,
            SweepCommand.Build(_options.Paths, _options.MaxEntries),
            _options.IntervalSeconds,
            cancellationToken).ConfigureAwait(false);

        if (outcome is null)
        {
            // The connection went away between listing it and using it. Not a problem worth
            // recording: the next round will find it gone.
            return false;
        }

        if (outcome.ExitCode is not (0 or 1))
        {
            // find exits 1 when some path could not be read, which is ordinary and still produces
            // usable output. Anything else means the sweep did not happen - most likely a target
            // whose find has no -printf - and that is recorded rather than read as "no changes".
            _problems.Set(target.Name, sshUser, $"The sweep command exited {outcome.ExitCode}. "
                + "Change detection needs GNU find, for -printf.");
            return false;
        }

        _problems.Clear(target.Name, sshUser);

        var at = DateTimeOffset.UtcNow;
        var current = SweepCommand.Parse(outcome.Stdout);

        if (SweepCommand.CountRecords(outcome.Stdout) >= _options.MaxEntries)
        {
            _problems.Set(target.Name, sshUser, $"The sweep hit its {_options.MaxEntries}-entry "
                + "ceiling, so part of the watched tree was not looked at. Narrow watch.paths, or "
                + "raise watch.max_entries.");
        }

        if (!_seen.TryGetValue(key, out var previous))
        {
            // The first sweep establishes a baseline and reports nothing. Everything it sees is
            // "new" only in the sense that nothing was looked at before, and emitting the whole
            // tree as created files would fill the timeline with an event that did not happen.
            _seen[key] = current;
            _timeline.RecordSweep(target.Name, at, []);
            return true;
        }

        _seen[key] = current;
        _timeline.RecordSweep(target.Name, at, SweepCommand.Diff(previous, current, at));
        return true;
    }
}
