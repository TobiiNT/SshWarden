namespace SshWarden.Authorization;

/// <summary>A glob over absolute paths, matched segment by segment.</summary>
/// <remarks>
/// <para>
/// <c>*</c> and <c>?</c> stay inside one segment; <c>**</c> stands for any number of segments,
/// including none. So <c>/var/log/*</c> covers <c>/var/log/syslog</c> and not
/// <c>/var/log/nginx/access.log</c>, while <c>/var/log/**</c> covers both. A pattern written for a
/// directory cannot widen to everything under it by accident.
/// </para>
/// <para>
/// Comparison is <strong>ordinal and case-sensitive</strong>, unlike host names. Unix paths are
/// case-sensitive, so <c>/etc/Passwd</c> and <c>/etc/passwd</c> are two files - folding case here
/// would make a rule cover something it does not name, which is the direction that matters.
/// </para>
/// <para>
/// <strong>This is layer one, and the README says so.</strong> It refuses early, refuses clearly,
/// and writes a legible record - inside a process the target host does not trust and cannot verify.
/// What holds is the unix account: if the account a rule maps to cannot read <c>/etc/shadow</c>,
/// every traversal trick changes the error message and nothing else. If it can, no pattern here
/// helps.
/// </para>
/// </remarks>
public static class PathPattern
{
    /// <summary>The segment standing for any number of segments.</summary>
    public const string AnyDepth = "**";

    /// <summary>Whether <paramref name="path" /> matches <paramref name="pattern" />.</summary>
    /// <param name="pattern">The glob. Must be absolute.</param>
    /// <param name="path">An already-normalized absolute path.</param>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    public static bool Matches(string pattern, string path)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(path);

        var patternSegments = Segments(pattern);
        var pathSegments = Segments(path);

        // The same remembered-star loop as a single-segment glob, one level up: here the star is
        // `**` and the atoms are whole segments. Recursion would be shorter and would backtrack
        // exponentially on a pattern full of `**`, which is the shape somebody writes when they are
        // being careful rather than when they are attacking.
        var patternIndex = 0;
        var pathIndex = 0;
        var starIndex = -1;
        var matchIndex = 0;

        while (pathIndex < pathSegments.Length)
        {
            if (patternIndex < patternSegments.Length
                && patternSegments[patternIndex] != AnyDepth
                && Glob.Matches(patternSegments[patternIndex], pathSegments[pathIndex]))
            {
                patternIndex++;
                pathIndex++;
            }
            else if (patternIndex < patternSegments.Length && patternSegments[patternIndex] == AnyDepth)
            {
                starIndex = patternIndex;
                matchIndex = pathIndex;
                patternIndex++;
            }
            else if (starIndex != -1)
            {
                patternIndex = starIndex + 1;
                matchIndex++;
                pathIndex = matchIndex;
            }
            else
            {
                return false;
            }
        }

        while (patternIndex < patternSegments.Length && patternSegments[patternIndex] == AnyDepth)
        {
            patternIndex++;
        }

        return patternIndex == patternSegments.Length;
    }

    /// <summary>Whether <paramref name="pattern" /> is one this matcher can use.</summary>
    /// <param name="pattern">The candidate.</param>
    /// <param name="problem">Why not, when this returns <see langword="false" />.</param>
    /// <exception cref="ArgumentNullException"><paramref name="pattern" /> is null.</exception>
    public static bool IsValid(string pattern, out string problem)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        if (!pattern.StartsWith('/'))
        {
            problem = "is not absolute; a path rule has to start with '/', because what a relative "
                + "path means depends on where the command happened to be run";
            return false;
        }

        foreach (var segment in Segments(pattern))
        {
            if (segment.Length == 0)
            {
                problem = "has an empty segment";
                return false;
            }

            if (segment is ".." or ".")
            {
                problem = "contains '" + segment + "', which a rule must not: a pattern that walks "
                    + "upwards describes a different set depending on where matching starts, and "
                    + "the point of a rule is that reading it tells you what it covers";
                return false;
            }

            if (segment.Contains(AnyDepth, StringComparison.Ordinal) && segment != AnyDepth)
            {
                problem = "has '**' inside a segment ('" + segment + "'). '**' stands for whole "
                    + "segments, so it has to be one on its own";
                return false;
            }
        }

        problem = string.Empty;
        return true;
    }

    /// <summary>Puts a caller-supplied path into the one form the matcher compares.</summary>
    /// <param name="path">The path as the caller wrote it.</param>
    /// <param name="normalized">The normalized path, when this returns <see langword="true" />.</param>
    /// <param name="problem">Why not, when this returns <see langword="false" />.</param>
    /// <exception cref="ArgumentNullException"><paramref name="path" /> is null.</exception>
    /// <remarks>
    /// <para>
    /// <c>..</c> is <strong>refused</strong> rather than resolved, and that is the stronger answer.
    /// Resolving it means the string the rule was checked against and the string the caller wrote
    /// are different, and every later reader has to work out which one they are looking at. No
    /// caller naming a file it is allowed to read needs to walk upwards to get there, so the whole
    /// class goes away for the cost of one refusal.
    /// </para>
    /// <para>
    /// This handles the traversal trap and nothing else. A path with no <c>..</c> in it can still
    /// point somewhere else entirely through a symlink on the target, which cannot be seen from
    /// here - that is resolved on the far side and checked again.
    /// </para>
    /// </remarks>
    public static bool TryNormalize(string path, out string normalized, out string problem)
    {
        ArgumentNullException.ThrowIfNull(path);

        normalized = string.Empty;

        if (!path.StartsWith('/'))
        {
            problem = "The path must be absolute. A relative path means something different "
                + "depending on where the command ran, and there is no session here for it to mean "
                + "it relative to.";
            return false;
        }

        var segments = new List<string>();
        foreach (var segment in Segments(path))
        {
            if (segment.Length == 0 || segment == ".")
            {
                // An empty segment is a doubled slash and a '.' is a no-op; both mean the same path
                // written differently, and neither can be used to reach anywhere new.
                continue;
            }

            if (segment == "..")
            {
                problem = "The path contains '..'. SshWarden refuses those rather than resolving "
                    + "them, so that the path a rule was checked against is the path that gets "
                    + "read. Name the file directly.";
                return false;
            }

            segments.Add(segment);
        }

        normalized = "/" + string.Join('/', segments);
        problem = string.Empty;
        return true;
    }

    private static string[] Segments(string value)
        => value.TrimEnd('/').Split('/', StringSplitOptions.None)[1..];
}
