namespace SshWarden.Changes;

/// <summary>What each host's watched paths have done lately.</summary>
/// <remarks>
/// <para>
/// A timeline rather than a snapshot taken around each command, and that is what closes the hole an
/// earlier design had: <c>list_changes(sinceMinutes)</c> needs something to compare against, and
/// "the state before this command" is not an answer to "what changed in the last ten minutes".
/// </para>
/// <para>
/// <strong>It also records when each sweep ran</strong>, not only what each sweep found. Without
/// that, a command's record could say which changes overlapped it but not how much of it was
/// actually looked at - and those are different claims. A command that ended between two sweeps has
/// a window narrower than its own duration, and saying so is the whole reason the field exists.
/// </para>
/// <para>
/// <strong>In memory, and per process.</strong> A restart loses it, and a second instance of this
/// server has its own. That is a real limit rather than an implementation detail: nothing here
/// survives a deploy, and the audit log - which does - carries what was attributed to each command
/// at the time.
/// </para>
/// </remarks>
public sealed class ChangeTimeline
{
    private readonly Lock _lock = new();
    private readonly Dictionary<string, HostTimeline> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _retention;

    /// <summary>Builds the timeline.</summary>
    /// <param name="retention">How far back to keep entries.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="retention" /> is not positive.</exception>
    public ChangeTimeline(TimeSpan retention)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(retention, TimeSpan.Zero);
        _retention = retention;
    }

    /// <summary>Records that a sweep of <paramref name="host" /> completed, and what it found.</summary>
    /// <param name="host">The host.</param>
    /// <param name="at">When the sweep ran.</param>
    /// <param name="changes">What it found, possibly none.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public void RecordSweep(string host, DateTimeOffset at, IReadOnlyList<FileChange> changes)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(changes);

        lock (_lock)
        {
            var timeline = Timeline(host);
            timeline.Sweeps.Add(at);
            timeline.Changes.AddRange(changes);
            Trim(timeline, at);
        }
    }

    /// <summary>What changed on <paramref name="host" /> in the last <paramref name="window" />.</summary>
    /// <param name="host">The host.</param>
    /// <param name="window">How far back to look.</param>
    /// <param name="now">The moment to measure back from.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public IReadOnlyList<FileChange> Since(string host, TimeSpan window, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(host);
        return Between(host, now - window, now);
    }

    /// <summary>What changed on <paramref name="host" /> between two moments.</summary>
    /// <param name="host">The host.</param>
    /// <param name="from">Exclusive lower bound.</param>
    /// <param name="to">Inclusive upper bound.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    /// <remarks>
    /// Deduplicated on path and kind. One host can be swept through more than one connection - a
    /// sweep runs as whichever unix account is already connected - and two accounts noticing the
    /// same edit is one edit, not two.
    /// </remarks>
    public IReadOnlyList<FileChange> Between(string host, DateTimeOffset from, DateTimeOffset to)
    {
        ArgumentNullException.ThrowIfNull(host);

        lock (_lock)
        {
            if (!_hosts.TryGetValue(host, out var timeline))
            {
                return [];
            }

            var seen = new HashSet<(string Path, string Kind)>();
            var result = new List<FileChange>();

            foreach (var change in timeline.Changes)
            {
                if (change.At > from && change.At <= to && seen.Add((change.Path, change.Kind)))
                {
                    result.Add(change);
                }
            }

            return result;
        }
    }

    /// <summary>The most recent sweep of <paramref name="host" /> at or before <paramref name="when" />.</summary>
    /// <param name="host">The host.</param>
    /// <param name="when">The moment.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public DateTimeOffset? LastSweepAtOrBefore(string host, DateTimeOffset when)
    {
        ArgumentNullException.ThrowIfNull(host);

        lock (_lock)
        {
            if (!_hosts.TryGetValue(host, out var timeline))
            {
                return null;
            }

            DateTimeOffset? found = null;
            foreach (var sweep in timeline.Sweeps)
            {
                if (sweep <= when && (found is null || sweep > found))
                {
                    found = sweep;
                }
            }

            return found;
        }
    }

    /// <summary>The most recent sweep of <paramref name="host" />.</summary>
    /// <param name="host">The host.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public DateTimeOffset? LastSweep(string host)
    {
        ArgumentNullException.ThrowIfNull(host);

        lock (_lock)
        {
            return _hosts.TryGetValue(host, out var timeline) && timeline.Sweeps.Count > 0
                ? timeline.Sweeps[^1]
                : null;
        }
    }

    private HostTimeline Timeline(string host)
    {
        if (!_hosts.TryGetValue(host, out var timeline))
        {
            timeline = new HostTimeline();
            _hosts[host] = timeline;
        }

        return timeline;
    }

    private void Trim(HostTimeline timeline, DateTimeOffset now)
    {
        var cutoff = now - _retention;

        _ = timeline.Changes.RemoveAll(change => change.At < cutoff);
        _ = timeline.Sweeps.RemoveAll(sweep => sweep < cutoff);
    }

    private sealed class HostTimeline
    {
        public List<DateTimeOffset> Sweeps { get; } = [];

        public List<FileChange> Changes { get; } = [];
    }
}
