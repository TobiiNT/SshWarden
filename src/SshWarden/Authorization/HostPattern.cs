namespace SshWarden.Authorization;

/// <summary>
/// A glob over host names, matched label by label.
/// </summary>
/// <remarks>
/// <para>
/// Glob and not regex, and that is a security decision rather than a convenience one. A regex in a
/// config file is a denial-of-service waiting for the wrong input, and - more to the point here -
/// somebody who writes an incorrect regex does not find out. <c>prod-.*</c> looks like it names the
/// production hosts and also matches <c>prod-.anything</c>; a mistake in a glob produces no match
/// rather than a surprising one, and no match is refused.
/// </para>
/// <para>
/// <c>*</c> and <c>?</c> do not cross a dot. <c>dev-*</c> matches <c>dev-web-1</c> and not
/// <c>dev.internal</c>, so a pattern written for a short name cannot silently widen to a whole
/// domain when somebody starts using fully qualified ones.
/// </para>
/// </remarks>
public static class HostPattern
{
    /// <summary>Whether <paramref name="host" /> matches <paramref name="pattern" />.</summary>
    /// <param name="pattern">The glob, for example <c>dev-*</c> or <c>prod-web-1</c>.</param>
    /// <param name="host">The host name to test.</param>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    public static bool Matches(string pattern, string host)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(host);

        var patternLabels = pattern.Split('.');
        var hostLabels = host.Split('.');

        // A pattern names as many labels as it names. Letting a short pattern match a longer host
        // would mean `dev-web` also covers `dev-web.customer.example`, which is a different machine.
        if (patternLabels.Length != hostLabels.Length)
        {
            return false;
        }

        for (var index = 0; index < patternLabels.Length; index++)
        {
            // Ordinal-ignore-case: host names are case-insensitive by RFC 4343, and a
            // culture-aware fold can disagree with every other implementation about which
            // characters are the same letter.
            if (!Glob.Matches(patternLabels[index], hostLabels[index], ignoreCase: true))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Whether a pattern is one this matcher can use.</summary>
    /// <param name="pattern">The candidate pattern.</param>
    /// <param name="problem">Why not, when this returns <see langword="false" />.</param>
    /// <exception cref="ArgumentNullException"><paramref name="pattern" /> is null.</exception>
    /// <remarks>
    /// Checked when the config is loaded rather than when a call arrives, so a pattern that can
    /// never match anything is a startup failure instead of a host that is quietly unreachable.
    /// </remarks>
    public static bool IsValid(string pattern, out string problem)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        if (pattern.Length == 0)
        {
            problem = "is empty";
            return false;
        }

        foreach (var label in pattern.Split('.'))
        {
            if (label.Length == 0)
            {
                problem = "has an empty label, so it can never match a host name";
                return false;
            }
        }

        // `**` is the path syntax, and a reader who has seen it there will reach for it here. It is
        // refused rather than quietly treated as `*`, because the two would differ exactly where
        // somebody was relying on it: `prod.**` reads as "everything under prod".
        if (pattern.Contains("**", StringComparison.Ordinal))
        {
            problem = "contains '**', which is path syntax; a host glob uses '*' and does not "
                + "cross a dot";
            return false;
        }

        problem = string.Empty;
        return true;
    }

}
