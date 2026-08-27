namespace SshWarden.Authorization;

/// <summary>A glob over service unit names.</summary>
/// <remarks>
/// <para>
/// Matched whole rather than split on anything. A unit name carries dots and <c>@</c> that are part
/// of the name rather than structure - <c>nginx.service</c>, <c>getty@tty1.service</c> - so the
/// label-by-label matching a host name gets would make <c>nginx*</c> fail to cover
/// <c>nginx.service</c>, which is the pattern everybody writes first.
/// </para>
/// <para>
/// Ordinal and case-sensitive: systemd unit names are.
/// </para>
/// </remarks>
public static class UnitPattern
{
    /// <summary>Whether <paramref name="unit" /> matches <paramref name="pattern" />.</summary>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    public static bool Matches(string pattern, string unit)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(unit);

        return Glob.Matches(pattern, unit);
    }

    /// <summary>Whether <paramref name="pattern" /> is one this matcher can use.</summary>
    /// <param name="pattern">The candidate.</param>
    /// <param name="problem">Why not, when this returns <see langword="false" />.</param>
    /// <exception cref="ArgumentNullException"><paramref name="pattern" /> is null.</exception>
    public static bool IsValid(string pattern, out string problem)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        if (pattern.Length == 0)
        {
            problem = "is empty";
            return false;
        }

        if (pattern.Contains('/', StringComparison.Ordinal))
        {
            // A caller's argument is read as a path when it starts with '/', so a unit rule
            // containing one could never fire. Refused rather than left to never match, because a
            // rule that cannot match looks exactly like a rule that is working.
            problem = "contains '/', so it is a path rather than a unit name. Put it in 'paths'";
            return false;
        }

        problem = string.Empty;
        return true;
    }
}
