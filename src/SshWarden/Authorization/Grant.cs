namespace SshWarden.Authorization;

/// <summary>One rule in the grant table: who may run what, where, and as which unix account.</summary>
/// <remarks>
/// The shape docs/DESIGN.md §6.5.4 settles on. Two layers of authority meet here - what the token says
/// (<see cref="Scopes" />) and what the deployment configured (everything else) - and a call needs
/// both.
/// </remarks>
public sealed class Grant
{
    /// <summary>A stable identifier for this rule, written to the audit record.</summary>
    /// <remarks>
    /// <para>
    /// Required, and written by the operator rather than derived from position, because it is what a
    /// dashboard query and an alert rule match on. An identifier derived from the block's index
    /// renumbers when somebody inserts a rule above it, which silently re-points every saved query
    /// at a different rule - the failure a stable identifier exists to prevent.
    /// </para>
    /// </remarks>
    public required string Id { get; init; }

    /// <summary>Whose calls this rule applies to. Compared ordinally.</summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The scopes a token must carry for this rule to apply. Empty means the rule needs none.
    /// </summary>
    /// <remarks>
    /// Empty is the normal case for a static-token deployment, where no token carries a scope claim
    /// at all. It is not a way to bypass anything: the rest of the rule still has to match.
    /// </remarks>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>The tools this rule covers. Compared ordinally.</summary>
    public required IReadOnlyList<string> Tools { get; init; }

    /// <summary>The hosts this rule covers, as globs. See <see cref="HostPattern" />.</summary>
    public required IReadOnlyList<string> Hosts { get; init; }

    /// <summary>The paths this rule covers, as globs. See <see cref="PathPattern" />.</summary>
    /// <remarks>
    /// Empty means the rule covers no path at all, which is a refusal rather than a wildcard - the
    /// table is deny-by-default and an absent selector grants nothing. The config loader refuses a
    /// rule that grants a path-reading tool and lists no paths, because such a rule reaches nothing
    /// and reads as though it does.
    /// </remarks>
    public IReadOnlyList<string> Paths { get; init; } = [];

    /// <summary>The service units this rule covers, as globs. See <see cref="UnitPattern" />.</summary>
    public IReadOnlyList<string> Units { get; init; } = [];

    /// <summary>The unix account SshWarden connects as when this rule applies.</summary>
    /// <remarks>
    /// <para>
    /// <strong>This is the boundary that actually holds.</strong> Everything else in this type
    /// refuses early, refuses clearly and writes a legible record - and all of it runs inside a
    /// process the target host does not trust and cannot verify. What cannot be worked around is
    /// what this account is permitted to do once it is logged in.
    /// </para>
    /// <para>
    /// So the investment that matters is here and on the target machine: a narrow account that
    /// cannot read what it should not read, rather than more checks on this side. A rule pointing
    /// at an account with broad <c>sudo</c> is not restrained by any amount of code in this
    /// repository.
    /// </para>
    /// </remarks>
    public required string SshUser { get; init; }

    /// <summary>Whether this rule covers <paramref name="tool" />.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="tool" /> is null.</exception>
    public bool CoversTool(string tool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        // Ordinal. A tool name is matched character-for-character against what the MCP client sent;
        // two implementations must not disagree about it on a case fold.
        return Tools.Contains(tool, StringComparer.Ordinal);
    }

    /// <summary>Whether this rule covers <paramref name="host" />.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="host" /> is null.</exception>
    public bool CoversHost(string host)
    {
        ArgumentNullException.ThrowIfNull(host);
        return Hosts.Any(pattern => HostPattern.Matches(pattern, host));
    }

    /// <summary>Whether this rule covers <paramref name="path" />.</summary>
    /// <param name="path">An already-normalized absolute path.</param>
    /// <exception cref="ArgumentNullException"><paramref name="path" /> is null.</exception>
    public bool CoversPath(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return Paths.Any(pattern => PathPattern.Matches(pattern, path));
    }

    /// <summary>Whether this rule covers <paramref name="unit" />.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="unit" /> is null.</exception>
    public bool CoversUnit(string unit)
    {
        ArgumentNullException.ThrowIfNull(unit);
        return Units.Any(pattern => UnitPattern.Matches(pattern, unit));
    }
}
