using System.Globalization;

using SshWarden.Ssh;

namespace SshWarden.Changes;

/// <summary>The command a sweep runs, and how to read what it prints.</summary>
/// <remarks>
/// <para>
/// One <c>find</c> across every watched path, printing four fields per file. One command rather
/// than one per path, because the cost that matters is the round trip and the directory walk, not
/// the length of the argument list.
/// </para>
/// <para>
/// GNU <c>find</c>, for <c>-printf</c>. That is a real dependency and it is worth naming: on a
/// target without it the sweep produces nothing and change detection is silently off for that host.
/// The sweeper reports a sweep that returned nothing as a failure rather than as "no changes",
/// which is the difference between measuring zero and not measuring.
/// </para>
/// </remarks>
public static class SweepCommand
{
    /// <summary>Builds the sweep command for <paramref name="paths" />.</summary>
    /// <param name="paths">The watched paths.</param>
    /// <param name="maxEntries">The most files to report.</param>
    /// <exception cref="ArgumentNullException"><paramref name="paths" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="paths" /> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxEntries" /> is not positive.</exception>
    public static string Build(IReadOnlyList<string> paths, int maxEntries)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEntries);

        if (paths.Count == 0)
        {
            throw new ArgumentException("A sweep with no watched paths would scan nothing.", nameof(paths));
        }

        var quoted = string.Join(' ', paths.Select(ShellQuoting.Quote));

        // -xdev so a network mount under a watched path does not turn a sweep into a walk of
        // somebody else's filesystem every thirty seconds.
        //
        // Records separated by NUL and fields by tab, with the path last: a path may contain a
        // newline, so a line-oriented format would split one file into two records. Splitting each
        // record on the first three tabs leaves the path intact even if it contains tabs of its own.
        //
        // stderr discarded: a watched path the account cannot read produces one message per
        // directory, every interval, and what it means - this account does not see everything under
        // there - is a property of the deployment rather than an event.
        //
        // head -z bounds the output. A watched path with a million files under it would otherwise
        // move that list across the network on every sweep.
        return $"find {quoted} -xdev \\( -type f -o -type l \\) "
            + "-printf '%i\\t%s\\t%T@\\t%p\\0' 2>/dev/null | "
            + $"head -z -n {maxEntries}";
    }

    /// <summary>Reads what the sweep printed.</summary>
    /// <param name="output">The command's standard output.</param>
    /// <exception cref="ArgumentNullException"><paramref name="output" /> is null.</exception>
    /// <remarks>
    /// A record that does not parse is skipped rather than failing the sweep. One malformed line -
    /// a filename doing something unexpected - should cost that file's entry, not every other
    /// file's.
    /// </remarks>
    public static Dictionary<string, FileState> Parse(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        var states = new Dictionary<string, FileState>(StringComparer.Ordinal);

        foreach (var record in output.Split('\0', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = record.Split('\t', 4);
            if (fields.Length != 4)
            {
                continue;
            }

            if (!long.TryParse(fields[0], CultureInfo.InvariantCulture, out var inode)
                || !long.TryParse(fields[1], CultureInfo.InvariantCulture, out var size)
                || !double.TryParse(fields[2], CultureInfo.InvariantCulture, out var modified))
            {
                continue;
            }

            states[fields[3]] = new FileState(inode, size, modified);
        }

        return states;
    }

    /// <summary>Diffs two sweeps.</summary>
    /// <param name="previous">What the last sweep saw.</param>
    /// <param name="current">What this sweep saw.</param>
    /// <param name="at">When this sweep ran.</param>
    /// <exception cref="ArgumentNullException">Either dictionary is null.</exception>
    public static List<FileChange> Diff(
        IReadOnlyDictionary<string, FileState> previous,
        IReadOnlyDictionary<string, FileState> current,
        DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);

        var changes = new List<FileChange>();

        foreach (var (path, state) in current)
        {
            if (!previous.TryGetValue(path, out var before))
            {
                changes.Add(new FileChange { At = at, Path = path, Kind = FileChangeKinds.Created });
            }
            else if (before != state)
            {
                changes.Add(new FileChange { At = at, Path = path, Kind = FileChangeKinds.Modified });
            }
        }

        foreach (var path in previous.Keys)
        {
            if (!current.ContainsKey(path))
            {
                changes.Add(new FileChange { At = at, Path = path, Kind = FileChangeKinds.Deleted });
            }
        }

        // Ordered, so two sweeps of the same filesystem produce the same list in the same order and
        // a test can assert on it without sorting first.
        changes.Sort((left, right) => string.CompareOrdinal(left.Path, right.Path));
        return changes;
    }

    /// <summary>Describes a sweep's output size, for the log.</summary>
    /// <param name="output">The command's standard output.</param>
    /// <exception cref="ArgumentNullException"><paramref name="output" /> is null.</exception>
    public static int CountRecords(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        return output.AsSpan().Count('\0');
    }
}
