using System.Text;

namespace SshWarden.Output;

/// <summary>Cuts output down to a size, and says so in the text.</summary>
/// <remarks>
/// <para>
/// A command that prints four hundred thousand lines is not hypothetical - it is what
/// <c>journalctl</c> does in the first week. Returning all of it wastes the caller's context on
/// something it cannot use; returning part of it silently is worse, because a conclusion then gets
/// drawn from a fragment that looks whole.
/// </para>
/// <para>
/// So the cut is in the <strong>middle</strong>, and it announces itself. The head says what the
/// command was doing and the tail says how it ended, which is where the error usually is - the tail
/// gets the larger share for that reason.
/// </para>
/// </remarks>
public static class OutputBudget
{
    /// <summary>
    /// The share of the budget given to the head; the rest goes to the tail.
    /// </summary>
    /// <remarks>
    /// A third, so the end of the output gets twice the room. A command that failed says why on its
    /// last few lines far more often than on its first.
    /// </remarks>
    private const double HeadShare = 1.0 / 3.0;

    /// <summary>Cuts <paramref name="text" /> to <paramref name="maxBytes" />.</summary>
    /// <param name="text">The text.</param>
    /// <param name="maxBytes">The most UTF-8 bytes to keep, excluding the marker.</param>
    /// <exception cref="ArgumentNullException"><paramref name="text" /> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxBytes" /> is not positive.</exception>
    public static BudgetResult Apply(string text, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);

        var totalBytes = Encoding.UTF8.GetByteCount(text);
        if (totalBytes <= maxBytes)
        {
            return new BudgetResult { Text = text, Truncated = false, DroppedBytes = 0, DroppedLines = 0 };
        }

        var headBudget = (int)(maxBytes * HeadShare);
        var tailBudget = maxBytes - headBudget;

        // Whole lines from each end. Cutting mid-line would produce a fragment that reads as a
        // complete line and is not one - which is the same class of quiet wrongness as cutting the
        // output without saying so, one level down.
        var lines = text.Split('\n');

        var headLines = TakeWholeLines(lines, headBudget, fromStart: true);
        var tailLines = TakeWholeLines(lines, tailBudget, fromStart: false);

        // Both ends empty means one line longer than the whole budget - a `cat` of something with
        // no newlines in it. Whole lines cannot help, so the fallback cuts by characters at a
        // boundary that does not split a surrogate pair.
        if (headLines == 0 && tailLines == 0)
        {
            return CutWithoutLines(text, totalBytes, headBudget, tailBudget);
        }

        // Overlap means the two ends together already cover everything; nothing was dropped after
        // all, so nothing is claimed to have been.
        if (headLines + tailLines >= lines.Length)
        {
            return new BudgetResult { Text = text, Truncated = false, DroppedBytes = 0, DroppedLines = 0 };
        }

        var head = string.Join('\n', lines[..headLines]);
        var tail = string.Join('\n', lines[^tailLines..]);

        var droppedLines = lines.Length - headLines - tailLines;
        var keptBytes = Encoding.UTF8.GetByteCount(head) + Encoding.UTF8.GetByteCount(tail);

        return new BudgetResult
        {
            Text = head + Marker(droppedLines, totalBytes - keptBytes) + tail,
            Truncated = true,
            DroppedBytes = totalBytes - keptBytes,
            DroppedLines = droppedLines,
        };
    }

    private static string Marker(int droppedLines, long droppedBytes)
        => $"\n[... SshWarden truncated {droppedLines} lines, {droppedBytes} bytes ...]\n";

    private static int TakeWholeLines(string[] lines, int budget, bool fromStart)
    {
        var used = 0;
        var taken = 0;

        for (var index = 0; index < lines.Length; index++)
        {
            var line = fromStart ? lines[index] : lines[^(index + 1)];

            // The newline that joins it back on.
            var cost = Encoding.UTF8.GetByteCount(line) + 1;
            if (used + cost > budget)
            {
                break;
            }

            used += cost;
            taken++;
        }

        return taken;
    }

    private static BudgetResult CutWithoutLines(string text, int totalBytes, int headBudget, int tailBudget)
    {
        var head = text[..SafeLength(text, headBudget)];
        var tailStart = text.Length - SafeLength(text, tailBudget, fromEnd: true);
        var tail = text[tailStart..];

        var keptBytes = Encoding.UTF8.GetByteCount(head) + Encoding.UTF8.GetByteCount(tail);

        return new BudgetResult
        {
            // Zero dropped lines, honestly: there were none to drop. Reporting a line count here
            // would be inventing a number for output that has no lines in it.
            Text = head + Marker(0, totalBytes - keptBytes) + tail,
            Truncated = true,
            DroppedBytes = totalBytes - keptBytes,
            DroppedLines = 0,
        };
    }

    private static int SafeLength(string text, int budget, bool fromEnd = false)
    {
        var used = 0;
        var count = 0;

        while (count < text.Length)
        {
            var index = fromEnd ? text.Length - count - 1 : count;

            // A surrogate pair is one character in two UTF-16 units. Stopping between them would
            // leave half a character, which is not text in any encoding.
            var isPairStart = fromEnd
                ? char.IsLowSurrogate(text[index]) && index > 0 && char.IsHighSurrogate(text[index - 1])
                : char.IsHighSurrogate(text[index]) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]);

            var step = isPairStart ? 2 : 1;
            var slice = fromEnd ? text.Substring(index - step + 1, step) : text.Substring(index, step);
            var cost = Encoding.UTF8.GetByteCount(slice);

            if (used + cost > budget)
            {
                break;
            }

            used += cost;
            count += step;
        }

        return count;
    }
}

/// <summary>What the budget did to one piece of text.</summary>
public sealed class BudgetResult
{
    /// <summary>The text, with a marker in place of whatever was dropped.</summary>
    public required string Text { get; init; }

    /// <summary>Whether anything was dropped.</summary>
    public required bool Truncated { get; init; }

    /// <summary>How many bytes were dropped.</summary>
    public required long DroppedBytes { get; init; }

    /// <summary>How many whole lines were dropped.</summary>
    public required int DroppedLines { get; init; }
}
