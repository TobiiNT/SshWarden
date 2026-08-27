using System.Collections.Concurrent;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using SshWarden.Diagnostics;

namespace SshWarden.Changes;

/// <summary>What the last sweep of each host and account could not do.</summary>
/// <remarks>
/// <para>
/// Its own type rather than a property of the sweeper, so the tool that reports these does not have
/// to hold a reference to the thing that produces them - and therefore does not drag the SSH
/// connection pool into a deployment that watches nothing.
/// </para>
/// <para>
/// It exists at all because "nothing changed" and "the sweep did not run" produce the same empty
/// list and mean opposite things. A target whose <c>find</c> has no <c>-printf</c>, a watched tree
/// too large for the ceiling, a host nothing has connected to - each of those is an answer, and
/// none of them is "no changes".
/// </para>
/// </remarks>
public sealed class SweepProblems
{
    private readonly ConcurrentDictionary<(string Host, string SshUser), string> _problems = new();
    private readonly ILogger _logger;

    /// <summary>Builds the collector.</summary>
    /// <param name="logger">Where a problem and its recovery are announced.</param>
    /// <remarks>
    /// <para>
    /// <strong>The logging is here rather than in the sweeper, and that is the point.</strong> Every
    /// path that has a problem to report already goes through <see cref="Set" /> and every path that
    /// clears one goes through <see cref="Clear" />, so this is the one place both transitions are
    /// visible. Logging at the four call sites instead would be four chances to add a fifth and
    /// forget.
    /// </para>
    /// <para>
    /// Optional, defaulting to the null logger, because this type is constructed directly in tests
    /// and in a deployment that watches nothing - and a collector that will not exist without a
    /// logging stack would put a logging dependency in front of a feature that does not log.
    /// </para>
    /// </remarks>
    public SweepProblems(ILogger<SweepProblems>? logger = null)
        => _logger = logger ?? (ILogger)NullLogger.Instance;

    /// <summary>Records that a sweep had a problem.</summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public void Set(string host, string sshUser, string problem)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(sshUser);
        ArgumentNullException.ThrowIfNull(problem);

        // On a change of state, not on every round. The sweeper runs on a timer, so a host that has
        // been unreachable since Tuesday would otherwise produce one identical warning per interval
        // until somebody stops reading them - which is the same as not logging it.
        var changed = !_problems.TryGetValue((host, sshUser), out var previous)
            || !string.Equals(previous, problem, StringComparison.Ordinal);

        _problems[(host, sshUser)] = problem;

        if (changed)
        {
            CoreLog.SweepProblem(_logger, host, sshUser, problem);
        }
    }

    /// <summary>Records that a sweep succeeded.</summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public void Clear(string host, string sshUser)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(sshUser);

        // The recovery is the news; a sweep that has always worked is not. Clear is called after
        // every successful sweep, so announcing unconditionally would bury the warning above under
        // one line per host per interval.
        if (_problems.TryRemove((host, sshUser), out _))
        {
            CoreLog.SweepRecovered(_logger, host, sshUser);
        }
    }

    /// <summary>What is wrong with sweeping <paramref name="host" />, if anything.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public IReadOnlyList<string> For(string host)
    {
        ArgumentNullException.ThrowIfNull(host);

        return [.. _problems
            .Where(entry => string.Equals(entry.Key.Host, host, StringComparison.OrdinalIgnoreCase))
            .Select(entry => $"The last sweep as '{entry.Key.SshUser}' had a problem: {entry.Value}")];
    }
}
