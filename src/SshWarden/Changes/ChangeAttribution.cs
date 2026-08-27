namespace SshWarden.Changes;

/// <summary>Works out which changes to put on a command's record, and how much that is worth.</summary>
/// <remarks>
/// One place rather than three call sites doing the arithmetic, because the window is easy to get
/// subtly wrong and the wrong answer is not obviously wrong: a window taken as the command's own
/// duration would claim the sweeper looked at a span it did not, and the empty list that follows
/// would read as "nothing changed".
/// </remarks>
public sealed class ChangeAttribution
{
    private readonly ChangeTimeline _timeline;
    private readonly CommandOverlap _overlap;

    /// <summary>Builds the attributor.</summary>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    public ChangeAttribution(ChangeTimeline timeline, CommandOverlap overlap)
    {
        ArgumentNullException.ThrowIfNull(timeline);
        ArgumentNullException.ThrowIfNull(overlap);

        _timeline = timeline;
        _overlap = overlap;
    }

    /// <summary>Records that a command has started, and returns its token.</summary>
    /// <param name="host">The host.</param>
    /// <param name="startedAt">When it started.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public long Begin(string host, DateTimeOffset startedAt) => _overlap.Begin(host, startedAt);

    /// <summary>Closes a command's span and works out what to record.</summary>
    /// <param name="host">The host.</param>
    /// <param name="id">The token from <see cref="Begin" />.</param>
    /// <param name="startedAt">When the command started.</param>
    /// <param name="endedAt">When it ended.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public AttributedChanges Finish(string host, long id, DateTimeOffset startedAt, DateTimeOffset endedAt)
    {
        ArgumentNullException.ThrowIfNull(host);

        _overlap.Finish(host, id, endedAt);

        // The window is bounded by sweeps, not by the command. Its start is the last sweep at or
        // before the command started - anything the sweeper found after that is a change it had not
        // yet seen when the command began. Its end is the last sweep of all, which may be before
        // the command ended; that is the honest answer, and the alternative - waiting for one more
        // sweep - would add the whole interval to every call's latency.
        var windowStart = _timeline.LastSweepAtOrBefore(host, startedAt);
        var windowEnd = _timeline.LastSweep(host);

        if (windowStart is null || windowEnd is null || windowEnd <= windowStart)
        {
            // No sweep covered this command. Zero, and an empty list that the zero explains.
            return new AttributedChanges
            {
                Changes = [],
                WindowMs = 0,
                Confidence = _overlap.Describe(host, id, startedAt, endedAt, endedAt),
            };
        }

        return new AttributedChanges
        {
            Changes = _timeline.Between(host, windowStart.Value, windowEnd.Value),
            WindowMs = (long)(windowEnd.Value - windowStart.Value).TotalMilliseconds,
            Confidence = _overlap.Describe(host, id, windowStart.Value, windowEnd.Value, endedAt),
        };
    }
}

/// <summary>What a command's record says about changes.</summary>
public sealed class AttributedChanges
{
    /// <summary>The changes the sweeper saw in the window.</summary>
    public required IReadOnlyList<FileChange> Changes { get; init; }

    /// <summary>How much time the sweeper actually looked at.</summary>
    public required long WindowMs { get; init; }

    /// <summary>Whether anything else was running on that host during the window.</summary>
    public required string Confidence { get; init; }
}
