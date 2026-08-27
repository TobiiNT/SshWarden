namespace SshWarden.Authorization;

/// <summary>Whether a call may proceed, and which rule decided.</summary>
/// <remarks>
/// Both halves are always present. An allowed call carries the rule that allowed it, because that
/// rule also names the unix account the command will run as - and a record that says a command ran
/// without saying who it ran as fails docs/DESIGN.md §4.2's test.
/// </remarks>
public sealed class AuthorizationDecision
{
    private AuthorizationDecision(Grant? grant, string? refusedBy, string? detail)
    {
        Grant = grant;
        RefusedBy = refusedBy;
        Detail = detail;
    }

    /// <summary>Whether the call may proceed.</summary>
    public bool IsAllowed => Grant is not null;

    /// <summary>The rule that allowed the call; <see langword="null" /> when refused.</summary>
    public Grant? Grant { get; }

    /// <summary>
    /// Which rule refused, as one of the <see cref="AuthorizationRefusal" /> identifiers;
    /// <see langword="null" /> when allowed.
    /// </summary>
    public string? RefusedBy { get; }

    /// <summary>
    /// What to tell the caller. Says what was refused and which rule refused it, and names no host,
    /// subject or grant the caller has not already demonstrated they know about.
    /// </summary>
    public string? Detail { get; }

    /// <summary>The call may proceed under <paramref name="grant" />.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="grant" /> is null.</exception>
    public static AuthorizationDecision Allow(Grant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        return new AuthorizationDecision(grant, refusedBy: null, detail: null);
    }

    /// <summary>The call is refused.</summary>
    /// <param name="refusedBy">One of the <see cref="AuthorizationRefusal" /> identifiers.</param>
    /// <param name="detail">What to tell the caller.</param>
    /// <exception cref="ArgumentException">Either argument is null or whitespace.</exception>
    public static AuthorizationDecision Refuse(string refusedBy, string detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refusedBy);
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);
        return new AuthorizationDecision(grant: null, refusedBy, detail);
    }
}
