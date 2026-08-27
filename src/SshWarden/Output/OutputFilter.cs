using System.Text.RegularExpressions;

namespace SshWarden.Output;

/// <summary>Keeps only the lines matching a caller-supplied pattern.</summary>
/// <remarks>
/// <para>
/// Applied on this side rather than by piping the command through <c>grep</c> on the target, so it
/// works the same whether or not the host has <c>grep</c>, does not change the command's exit
/// status, and - the reason that matters - keeps the untouched output available to be measured and
/// masked before anything is thrown away.
/// </para>
/// <para>
/// <strong>The pattern comes from an agent</strong>, which makes it the one regular expression in
/// this project that untrusted input controls. It is compiled non-backtracking, so matching is
/// linear in the input and the catastrophic-backtracking shapes that turn a regex into a denial of
/// service simply do not exist for it. That is also why lookarounds and backreferences are refused
/// rather than supported: the engine that cannot blow up is the engine that does not have them, and
/// the trade is worth stating out loud rather than quietly falling back to the one that can.
/// </para>
/// </remarks>
public static class OutputFilter
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Keeps the lines of <paramref name="text" /> matching <paramref name="pattern" />.</summary>
    /// <param name="text">The text to filter.</param>
    /// <param name="pattern">The regular expression.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public static FilterResult Apply(string text, string pattern)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(pattern);

        Regex regex;
        try
        {
            regex = new Regex(pattern, RegexOptions.NonBacktracking, MatchTimeout);
        }
        catch (Exception invalid) when (invalid is ArgumentException or NotSupportedException)
        {
            // Two kinds of unusable, one answer. A pattern that will not parse throws
            // ArgumentException; one that parses and asks for a feature the non-backtracking engine
            // does not have - a lookaround, a backreference - throws NotSupportedException. Both
            // mean the filter did not run, and the caller needs to know that rather than which
            // exception type said so.

            // A pattern that will not compile is answered rather than swallowed. Returning the
            // unfiltered output would hand back far more than was asked for and look like a filter
            // that matched everything.
            return new FilterResult
            {
                Text = text,
                Applied = false,
                Problem = "The grep pattern was not usable: " + invalid.Message
                    + " Note that lookarounds and backreferences are not supported - the matcher is "
                    + "non-backtracking so that a pattern cannot become a denial of service.",
            };
        }

        var lines = text.Split('\n');
        var kept = new List<string>();

        try
        {
            foreach (var line in lines)
            {
                if (regex.IsMatch(line))
                {
                    kept.Add(line);
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return new FilterResult
            {
                Text = text,
                Applied = false,
                Problem = "The grep pattern took too long against this output and was abandoned.",
            };
        }

        return new FilterResult
        {
            Text = string.Join('\n', kept),
            Applied = true,
            KeptLines = kept.Count,
            TotalLines = lines.Length,
        };
    }
}

/// <summary>What filtering did to one piece of text.</summary>
public sealed class FilterResult
{
    /// <summary>The text - filtered when <see cref="Applied" />, otherwise unchanged.</summary>
    public required string Text { get; init; }

    /// <summary>Whether the filter ran.</summary>
    public required bool Applied { get; init; }

    /// <summary>Why it did not run, when it did not.</summary>
    public string? Problem { get; init; }

    /// <summary>How many lines matched.</summary>
    public int KeptLines { get; init; }

    /// <summary>How many lines there were.</summary>
    public int TotalLines { get; init; }
}
