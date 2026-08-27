using SshWarden.Auth;

namespace SshWarden.Authorization;

/// <summary>The configured rules, and the decision they produce for a call.</summary>
/// <remarks>
/// <para>
/// Deny by default: a call is allowed only if some rule covers it, and no rule covering it is the
/// end of the matter. docs/DESIGN.md §6.5.4.
/// </para>
/// <para>
/// Immutable and pure. Deciding twice for one call - once in the gate and once in the tool, to find
/// the unix account - gives the same answer both times, which is why the two do not have to share
/// per-request state to stay consistent. Shared mutable state between a gate and the thing it gates
/// is the shape where they can come to disagree.
/// </para>
/// </remarks>
public sealed class GrantTable
{
    private readonly IReadOnlyList<Grant> _grants;

    /// <summary>Builds the table.</summary>
    /// <param name="grants">The rules, in the order they appear in the config file.</param>
    /// <exception cref="ArgumentNullException"><paramref name="grants" /> is null.</exception>
    public GrantTable(IReadOnlyList<Grant> grants)
    {
        ArgumentNullException.ThrowIfNull(grants);
        _grants = grants;
    }

    /// <summary>Every rule, in file order.</summary>
    public IReadOnlyList<Grant> Grants => _grants;

    /// <summary>
    /// Whether <paramref name="caller" /> may see and call <paramref name="tool" /> at all,
    /// ignoring its arguments.
    /// </summary>
    /// <remarks>
    /// This is the question <c>tools/list</c> asks, so a refusal here hides the tool rather than
    /// failing a call. Arguments are deliberately not considered: whether a tool is visible cannot
    /// depend on arguments a listing does not have.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public AuthorizationDecision AuthorizeTool(CallerIdentity caller, string tool)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(tool);

        var candidates = Candidates(caller, tool, out var refusal);
        return candidates.Count == 0
            ? Refuse(refusal!, tool, host: null)
            : AuthorizationDecision.Allow(candidates[0]);
    }

    /// <summary>
    /// Whether <paramref name="caller" /> may call <paramref name="tool" /> against
    /// <paramref name="host" />.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The host is the only argument of <c>run</c> that can be gated. The command cannot be:
    /// gating it would mean deciding what a shell will do with a string, which is not answerable at
    /// the string level and is a permanent non-goal of this project. The working directory cannot
    /// be either - a command is free to <c>cd</c> anywhere, so a directory selector is audit
    /// metadata rather than a boundary, and describing it as one would manufacture exactly the false
    /// confidence this design is trying to avoid.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public AuthorizationDecision AuthorizeHost(CallerIdentity caller, string tool, string host)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(host);

        var candidates = Candidates(caller, tool, out var refusal);
        if (candidates.Count == 0)
        {
            return Refuse(refusal!, tool, host);
        }

        // First match in file order wins, and the order is documented rather than incidental: two
        // rules may cover one host with two different unix accounts, and something has to choose.
        // The alternative - refusing the ambiguity - turns a working config into a startup failure
        // the day somebody adds an overlapping rule, which is worse than a documented order.
        var winner = candidates.FirstOrDefault(grant => grant.CoversHost(host));
        return winner is null
            ? Refuse(AuthorizationRefusal.HostNotGranted, tool, host)
            : AuthorizationDecision.Allow(winner);
    }

    /// <summary>
    /// Whether <paramref name="caller" /> may use <paramref name="tool" /> on
    /// <paramref name="path" />, at <paramref name="host" />.
    /// </summary>
    /// <param name="caller">Who is calling.</param>
    /// <param name="tool">The tool name.</param>
    /// <param name="host">The target host.</param>
    /// <param name="path">An already-normalized absolute path.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    /// <remarks>
    /// <para>
    /// One rule has to cover both the host and the path, not two rules covering one each. A caller
    /// allowed <c>/var/log/**</c> on a development machine and allowed a production machine for
    /// something else must not get production logs by combining them.
    /// </para>
    /// <para>
    /// Called twice per read, deliberately: once on the path the caller named, and once on what
    /// that path turned out to be after the target resolved it. The second call is what a symlink
    /// out of the allowed tree runs into.
    /// </para>
    /// </remarks>
    public AuthorizationDecision AuthorizePath(
        CallerIdentity caller,
        string tool,
        string host,
        string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        return AuthorizeSelector(
            caller,
            tool,
            host,
            grant => grant.CoversPath(path),
            AuthorizationRefusal.PathNotGranted,
            $"path '{path}'");
    }

    /// <summary>
    /// Whether <paramref name="caller" /> may use <paramref name="tool" /> on
    /// <paramref name="unit" />, at <paramref name="host" />.
    /// </summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public AuthorizationDecision AuthorizeUnit(
        CallerIdentity caller,
        string tool,
        string host,
        string unit)
    {
        ArgumentNullException.ThrowIfNull(unit);

        return AuthorizeSelector(
            caller,
            tool,
            host,
            grant => grant.CoversUnit(unit),
            AuthorizationRefusal.UnitNotGranted,
            $"unit '{unit}'");
    }

    private AuthorizationDecision AuthorizeSelector(
        CallerIdentity caller,
        string tool,
        string host,
        Func<Grant, bool> covers,
        string refusalWhenUncovered,
        string described)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(host);

        var candidates = Candidates(caller, tool, out var refusal);
        if (candidates.Count == 0)
        {
            return Refuse(refusal!, tool, host);
        }

        var atHost = candidates.Where(grant => grant.CoversHost(host)).ToList();
        if (atHost.Count == 0)
        {
            return Refuse(AuthorizationRefusal.HostNotGranted, tool, host);
        }

        var winner = atHost.FirstOrDefault(covers);
        return winner is null
            ? AuthorizationDecision.Refuse(
                refusalWhenUncovered,
                $"SshWarden refused tool '{tool}' on {described} at host '{host}': no configured "
                    + $"grant covers it (rule: {refusalWhenUncovered}).")
            : AuthorizationDecision.Allow(winner);
    }

    private List<Grant> Candidates(CallerIdentity caller, string tool, out string? refusal)
    {
        // The token's scope claim is read before anything else, because two of its three states are
        // refusals in themselves rather than inputs to a match. Collapsing them into "no scopes"
        // and falling through to the grant table is the fail-open this whole design exists to
        // close - see ScopeClaimState.
        if (caller.ScopeClaim == ScopeClaimState.Unreadable)
        {
            refusal = AuthorizationRefusal.UnreadableScopeClaim;
            return [];
        }

        if (caller.ScopeClaim == ScopeClaimState.Readable && caller.Scopes.Count == 0)
        {
            refusal = AuthorizationRefusal.EmptyScopeClaim;
            return [];
        }

        var forSubject = _grants
            .Where(grant => string.Equals(grant.Subject, caller.Subject, StringComparison.Ordinal))
            .ToList();

        if (forSubject.Count == 0)
        {
            refusal = AuthorizationRefusal.NoGrantForSubject;
            return [];
        }

        // Tool before scope, and the order is what makes the refusal useful rather than merely
        // true. Narrowing by scope first drops a rule that covers this tool but needs a scope the
        // token lacks, and the answer then comes out as "no rule lists this tool" - which sends
        // somebody to edit the server's config over a problem re-authorizing would have fixed.
        // Asking about the tool first means every later stage is talking about the tool the caller
        // actually named.
        var withTool = forSubject.Where(grant => grant.CoversTool(tool)).ToList();
        if (withTool.Count == 0)
        {
            refusal = AuthorizationRefusal.ToolNotGranted;
            return [];
        }

        var withScope = withTool.Where(grant => ScopeSatisfied(caller, grant)).ToList();
        if (withScope.Count == 0)
        {
            refusal = AuthorizationRefusal.ScopeNotGranted;
            return [];
        }

        refusal = null;
        return withScope;
    }

    private static bool ScopeSatisfied(CallerIdentity caller, Grant grant)
    {
        // Absent - and Unknown, which means nobody filled the state in - land here. The token said
        // nothing about scopes, so the grant table decides alone. That is the ordinary state for a
        // static token and for an authorization server that publishes no scopes, and it is
        // legitimate: the rest of the rule still has to match.
        if (caller.ScopeClaim != ScopeClaimState.Readable)
        {
            return true;
        }

        // Every scope the rule names, not any of them. A rule saying it needs two scopes is a rule
        // for a caller holding both.
        return grant.Scopes.All(scope => caller.Scopes.Contains(scope));
    }

    private static AuthorizationDecision Refuse(string refusal, string tool, string? host)
    {
        // The caller is told what was refused and which rule refused it, in that order, and nothing
        // about the shape of the table. Naming the hosts that would have worked, or the subjects
        // that are configured, would turn a refusal into a way to enumerate a deployment.
        var what = host is null ? $"tool '{tool}'" : $"tool '{tool}' against host '{host}'";

        var why = refusal switch
        {
            AuthorizationRefusal.UnreadableScopeClaim =>
                "the access token's scope claim could not be read, so it grants nothing",
            AuthorizationRefusal.EmptyScopeClaim =>
                "the access token's scope claim is empty, so it grants nothing",
            AuthorizationRefusal.ScopeNotGranted =>
                "the access token does not carry the scopes this operation needs",
            _ => "no configured grant covers it",
        };

        return AuthorizationDecision.Refuse(
            refusal,
            $"SshWarden refused {what}: {why} (rule: {refusal}).");
    }
}
