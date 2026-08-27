namespace SshWarden.Authorization;

/// <summary>
/// The stable identifiers the grant table refuses under, written to the audit record.
/// </summary>
/// <remarks>
/// <para>
/// Identifiers rather than sentences, because the audit record's <c>denied_by</c> is what a
/// dashboard filters on and what an alert fires from. A message is prose somebody will improve, and
/// every query built on it breaks silently when they do.
/// </para>
/// <para>
/// Each names the <strong>most specific stage that failed</strong>, not just "denied". The
/// difference between "no grant names this subject" and "a grant names them but not this host" is
/// the difference between a person who was never set up and a person reaching somewhere they should
/// not - and those want different responses.
/// </para>
/// </remarks>
public static class AuthorizationRefusal
{
    /// <summary>
    /// The token carried a scope claim that could not be parsed.
    /// </summary>
    /// <remarks>
    /// Refused rather than falling back to the grant table. An unparseable claim yields the same
    /// empty scope set as no claim at all, and falling back would grant a mangled token more than
    /// it asked for.
    /// </remarks>
    public const string UnreadableScopeClaim = "unreadable_scope_claim";

    /// <summary>The token carried a scope claim that granted nothing.</summary>
    /// <remarks>
    /// Also refused rather than falling back. A token minted with an empty scope set was written to
    /// grant nothing, and treating that as "said nothing" would widen it to whatever the grant
    /// table allows.
    /// </remarks>
    public const string EmptyScopeClaim = "empty_scope_claim";

    /// <summary>No grant in the table names this subject.</summary>
    public const string NoGrantForSubject = "no_grant_for_subject";

    /// <summary>
    /// Grants exist for this subject, but the token does not carry the scopes they require.
    /// </summary>
    /// <remarks>
    /// The one refusal here that re-authorizing can fix, which is why it is distinguishable from
    /// the rest. Every other identifier in this class is a config change on the server.
    /// </remarks>
    public const string ScopeNotGranted = "scope_not_granted";

    /// <summary>No grant covering this subject and scope lists this tool.</summary>
    public const string ToolNotGranted = "tool_not_granted";

    /// <summary>No grant that otherwise applies covers this host.</summary>
    public const string HostNotGranted = "host_not_granted";

    /// <summary>No grant that otherwise applies covers this path.</summary>
    public const string PathNotGranted = "path_not_granted";

    /// <summary>No grant that otherwise applies covers this service unit.</summary>
    public const string UnitNotGranted = "unit_not_granted";

    /// <summary>The path the caller named is not one this can decide about.</summary>
    /// <remarks>
    /// Relative, or containing <c>..</c>. Refused before any rule is consulted, because a rule
    /// cannot be checked against a string whose meaning depends on where it is read from.
    /// </remarks>
    public const string PathNotUsable = "path_not_usable";

    /// <summary>
    /// The path was covered by a rule, and resolving it on the target landed somewhere no rule
    /// covers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The symlink case, and it has its own identifier for a reason: it means a caller named
    /// something a rule allows and the target pointed it elsewhere. That is either a deployment
    /// whose directories are not what its rules assume, or somebody finding out what is reachable -
    /// and it is worth telling apart from an ordinary out-of-scope path on a dashboard.
    /// </para>
    /// </remarks>
    public const string PathEscapesGrant = "path_escapes_grant";

    /// <summary>The target has no such file.</summary>
    /// <remarks>
    /// Distinct from every refusal above: nothing was denied, the file is not there. Reporting it
    /// as a permission problem would send somebody to edit the grant table over a typo.
    /// </remarks>
    public const string PathNotFound = "path_not_found";

    /// <summary>The call named no host, or named one that is not a string.</summary>
    /// <remarks>
    /// Distinct from <see cref="HostNotGranted" /> on purpose: this one means the gate could not
    /// find the argument it gates on. Answering "not granted" would read as a policy decision when
    /// what actually happened is that the policy could not be evaluated - which is a defect in the
    /// tool's schema or in the policy's argument names, not in the caller's permissions.
    /// </remarks>
    public const string HostArgumentMissing = "host_argument_missing";

    /// <summary>There is no job with that identifier.</summary>
    /// <remarks>
    /// <para>
    /// The same answer a caller gets for somebody else's job that they are not allowed to see -
    /// deliberately. Distinguishing "no such job" from "not yours" would turn the identifier space
    /// into something worth searching: a caller could learn which identifiers exist without being
    /// allowed any of them.
    /// </para>
    /// <para>
    /// The audit record keeps the distinction, because the operator reading it is not the one being
    /// refused.
    /// </para>
    /// </remarks>
    public const string JobNotFound = "job_not_found";

    /// <summary>The job belongs to another subject.</summary>
    /// <remarks>
    /// Recorded, never returned as itself - see <see cref="JobNotFound" />. Without this check a
    /// caller polls another's job, reads their production output, and signals their processes,
    /// bypassing every host rule at once because the argument carries no host to check.
    /// </remarks>
    public const string JobNotOwned = "job_not_owned";

    /// <summary>The call named no job, or named one that is not a string.</summary>
    public const string JobArgumentMissing = "job_argument_missing";

    /// <summary>The call named no path, or named one that is not a string.</summary>
    /// <remarks>
    /// Like <see cref="HostArgumentMissing" />, this means the gate could not find the argument it
    /// gates on rather than that the caller lacks permission - a defect in the tool's schema or in
    /// the policy's argument names, which no edit to the grant table can fix.
    /// </remarks>
    public const string PathArgumentMissing = "path_argument_missing";

    /// <summary>Every reason in this class.</summary>
    /// <remarks>
    /// <para>
    /// It exists because these strings became a metric label, and a label's value set has to be
    /// finite and known - a series is memory, and a series whose name comes from something a caller
    /// chose is memory a caller can grow. Everything here is chosen by this server, so the set is
    /// closed; this list is what lets the recorder prove that rather than assume it.
    /// </para>
    /// <para>
    /// A test holds it to the constants by reflection, because a list of names kept by hand is a
    /// list that is right until the next one is added.
    /// </para>
    /// </remarks>
    public static readonly IReadOnlyList<string> All =
    [
        UnreadableScopeClaim, EmptyScopeClaim, NoGrantForSubject, ScopeNotGranted, ToolNotGranted,
        HostNotGranted, PathNotGranted, UnitNotGranted, PathNotUsable, PathEscapesGrant,
        PathNotFound, HostArgumentMissing, JobNotFound, JobNotOwned, JobArgumentMissing,
        PathArgumentMissing,
    ];
}
