namespace SshWarden.Changes;

/// <summary>Which commands were running on a host at the same time as which others.</summary>
/// <remarks>
/// <para>
/// The thing that lets a record say how much its list of changes is worth. A sweep sees that four
/// files under <c>/etc</c> changed; it cannot see which of the three commands running at that
/// moment did it. Nothing can - that information does not exist on the target, and the two ways of
/// pretending otherwise are to serialize commands per host (which destroys the concurrency the
/// whole design is built around) or to attribute anyway (which reports a guess as an observation).
/// </para>
/// <para>
/// So the record carries the changes <em>and</em> whether anything else was running. A reader can
/// then treat an <c>exclusive</c> record as attribution and an <c>overlapping</c> one as a list of
/// candidates, which is what each actually is.
/// </para>
/// </remarks>
public sealed class CommandOverlap
{
    /// <summary>The confidence value for a window nothing else overlapped.</summary>
    public const string Exclusive = "exclusive";

    private readonly Lock _lock = new();
    private readonly Dictionary<string, List<Span>> _byHost = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _retention;
    private long _nextId;

    /// <summary>Builds the tracker.</summary>
    /// <param name="retention">How long a finished command stays comparable.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="retention" /> is not positive.</exception>
    public CommandOverlap(TimeSpan retention)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(retention, TimeSpan.Zero);
        _retention = retention;
    }

    /// <summary>Records that a command has started on <paramref name="host" />.</summary>
    /// <param name="host">The host.</param>
    /// <param name="startedAt">When it started.</param>
    /// <returns>A token to pass to <see cref="Finish" /> and <see cref="Describe" />.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public long Begin(string host, DateTimeOffset startedAt)
    {
        ArgumentNullException.ThrowIfNull(host);

        lock (_lock)
        {
            var id = ++_nextId;

            if (!_byHost.TryGetValue(host, out var spans))
            {
                spans = [];
                _byHost[host] = spans;
            }

            spans.Add(new Span(id, startedAt, null));
            _ = spans.RemoveAll(span => span.EndedAt is { } ended && ended < startedAt - _retention);

            return id;
        }
    }

    /// <summary>Records that the command has finished.</summary>
    /// <param name="host">The host.</param>
    /// <param name="id">The token from <see cref="Begin" />.</param>
    /// <param name="endedAt">When it finished.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public void Finish(string host, long id, DateTimeOffset endedAt)
    {
        ArgumentNullException.ThrowIfNull(host);

        lock (_lock)
        {
            if (!_byHost.TryGetValue(host, out var spans))
            {
                return;
            }

            for (var index = 0; index < spans.Count; index++)
            {
                if (spans[index].Id == id)
                {
                    spans[index] = spans[index] with { EndedAt = endedAt };
                    return;
                }
            }
        }
    }

    /// <summary>How confident a window's changes are, for the command identified by <paramref name="id" />.</summary>
    /// <param name="host">The host.</param>
    /// <param name="id">The command's token.</param>
    /// <param name="from">The start of the window that was scanned.</param>
    /// <param name="to">The end of the window that was scanned.</param>
    /// <param name="now">The moment to treat unfinished commands as still running until.</param>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public string Describe(string host, long id, DateTimeOffset from, DateTimeOffset to, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(host);

        lock (_lock)
        {
            if (!_byHost.TryGetValue(host, out var spans))
            {
                return Exclusive;
            }

            var others = 0;
            foreach (var span in spans)
            {
                if (span.Id == id)
                {
                    continue;
                }

                // A command with no end yet is still running, so it overlaps everything up to now.
                var ended = span.EndedAt ?? now;
                if (span.StartedAt <= to && ended >= from)
                {
                    others++;
                }
            }

            return others == 0 ? Exclusive : $"overlapping:{others}";
        }
    }

    private readonly record struct Span(long Id, DateTimeOffset StartedAt, DateTimeOffset? EndedAt);
}
