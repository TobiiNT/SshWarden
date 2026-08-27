using System.Text;

namespace SshWarden.Output;

/// <summary>Everything that happens to a command's output between the host and the caller.</summary>
/// <remarks>
/// <para>
/// <strong>The order is the point, and it is fixed here rather than asked for in a comment
/// somewhere.</strong> Measure, then filter, then mask, then cut:
/// </para>
/// <list type="number">
///   <item>
///     <description>
///       <strong>Measure</strong> on what arrived, before anything touches it. Measuring later
///       reports a number about SshWarden's own processing rather than about what the host
///       produced, and the audit record is supposed to say the second.
///     </description>
///   </item>
///   <item>
///     <description>
///       <strong>Filter</strong>, because the caller asked for a subset and everything after this
///       is cheaper and more useful on the subset. Before masking rather than after, so the pattern
///       is matched against what the host actually printed - grepping masked text would report no
///       matches for content that is there.
///     </description>
///   </item>
///   <item>
///     <description><strong>Mask</strong> credential-shaped values.</description>
///   </item>
///   <item>
///     <description>
///       <strong>Cut</strong> to the budget - and this is last for a specific reason. A secret
///       lying across the cut is two fragments, and neither fragment matches the pattern that would
///       have caught the whole. Cutting first would let exactly the values this is trying to hold
///       back through the gap.
///     </description>
///   </item>
/// </list>
/// <para>
/// A single method rather than four the caller composes, so the order cannot be got wrong by
/// someone who did not know it mattered.
/// </para>
/// </remarks>
public static class OutputPipeline
{
    /// <summary>Prepares one stream of output for return.</summary>
    /// <param name="raw">What came off the wire.</param>
    /// <param name="grep">A pattern to keep only matching lines, or null.</param>
    /// <param name="maxBytes">The most bytes to hand back.</param>
    /// <exception cref="ArgumentNullException"><paramref name="raw" /> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxBytes" /> is not positive.</exception>
    public static PreparedOutput Prepare(string raw, string? grep, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(raw);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);

        var rawBytes = Encoding.UTF8.GetByteCount(raw);

        var filter = string.IsNullOrEmpty(grep)
            ? new FilterResult { Text = raw, Applied = false }
            : OutputFilter.Apply(raw, grep);

        var redaction = SecretRedactor.Redact(filter.Text);
        var budget = OutputBudget.Apply(redaction.Text, maxBytes);

        return new PreparedOutput
        {
            Text = budget.Text,
            RawBytes = rawBytes,
            Truncated = budget.Truncated,
            DroppedLines = budget.DroppedLines,
            RedactedCount = redaction.Count,
            RedactionIncomplete = redaction.TimedOut,
            FilterApplied = filter.Applied,
            FilterProblem = filter.Problem,
        };
    }
}

/// <summary>Output as the caller will see it, and what was done to get there.</summary>
public sealed class PreparedOutput
{
    /// <summary>The text to hand back.</summary>
    public required string Text { get; init; }

    /// <summary>How many bytes the host produced, before anything here touched it.</summary>
    public required long RawBytes { get; init; }

    /// <summary>Whether the budget dropped anything.</summary>
    public required bool Truncated { get; init; }

    /// <summary>How many lines the budget dropped.</summary>
    public int DroppedLines { get; init; }

    /// <summary>How many credential-shaped values were masked.</summary>
    public required int RedactedCount { get; init; }

    /// <summary>Whether masking did not finish, leaving the text only partly masked.</summary>
    public bool RedactionIncomplete { get; init; }

    /// <summary>Whether a requested filter actually ran.</summary>
    public bool FilterApplied { get; init; }

    /// <summary>Why a requested filter did not run.</summary>
    public string? FilterProblem { get; init; }
}
