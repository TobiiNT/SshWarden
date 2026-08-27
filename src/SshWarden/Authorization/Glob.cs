namespace SshWarden.Authorization;

/// <summary>Matching one piece of text against a pattern of <c>*</c> and <c>?</c>.</summary>
/// <remarks>
/// <para>
/// The primitive under every selector in the grant table. Glob and not regex throughout, and that
/// is a security decision rather than a convenience one: a regex in a config file is a denial of
/// service waiting for the wrong input, and - more to the point - somebody who writes an incorrect
/// regex does not find out. A mistake in a glob produces no match rather than a surprising one, and
/// no match is refused.
/// </para>
/// <para>
/// Separator handling lives in the callers, because it differs and the difference matters: a host
/// glob does not cross a dot, a path glob does not cross a slash unless it says <c>**</c>, and a
/// unit name is matched whole because it contains dots and <c>@</c> that mean nothing structural.
/// </para>
/// </remarks>
public static class Glob
{
    /// <summary>Whether <paramref name="value" /> matches <paramref name="pattern" />.</summary>
    /// <param name="pattern">The pattern.</param>
    /// <param name="value">The text to test.</param>
    /// <param name="ignoreCase">Whether to fold case, ordinally.</param>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    /// <remarks>
    /// Iterative with a remembered star position rather than recursive. A pattern of many stars
    /// against a long value is the input that turns the obvious backtracking implementation into
    /// the denial of service that choosing glob over regex was meant to avoid.
    /// </remarks>
    public static bool Matches(string pattern, string value, bool ignoreCase = false)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(value);

        var patternIndex = 0;
        var valueIndex = 0;
        var starIndex = -1;
        var matchIndex = 0;

        while (valueIndex < value.Length)
        {
            if (patternIndex < pattern.Length
                && (pattern[patternIndex] == '?' || Same(pattern[patternIndex], value[valueIndex], ignoreCase)))
            {
                patternIndex++;
                valueIndex++;
            }
            else if (patternIndex < pattern.Length && pattern[patternIndex] == '*')
            {
                starIndex = patternIndex;
                matchIndex = valueIndex;
                patternIndex++;
            }
            else if (starIndex != -1)
            {
                patternIndex = starIndex + 1;
                matchIndex++;
                valueIndex = matchIndex;
            }
            else
            {
                return false;
            }
        }

        while (patternIndex < pattern.Length && pattern[patternIndex] == '*')
        {
            patternIndex++;
        }

        return patternIndex == pattern.Length;
    }

    private static bool Same(char pattern, char value, bool ignoreCase)
        => ignoreCase
            ? char.ToLowerInvariant(pattern) == char.ToLowerInvariant(value)
            : pattern == value;
}
