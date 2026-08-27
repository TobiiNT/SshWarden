namespace SshWarden.Auth;

/// <summary>
/// Who is making a tool call, as five named values that every authenticator fills.
/// </summary>
/// <remarks>
/// <para>
/// docs/DESIGN.md §6.2 requires these to be <em>properties</em> rather than lookups into a claims
/// dictionary. A misspelled dictionary key compiles, returns null, and silently removes a gate; a
/// misspelled property name does not compile. Every one of the five flows straight into the audit
/// record of §4.2, which is the artefact the whole project exists to produce, so a null that
/// arrived by typo is a hole in the record nobody would notice.
/// </para>
/// <para>
/// The rest of SshWarden must not be able to tell which <see cref="ISshWardenAuthenticator" />
/// produced an instance. That is why <see cref="Source" /> is a label for the record rather than
/// something to branch on, and why nothing here is nullable-because-static-tokens-are-different:
/// both implementations fill all five.
/// </para>
/// </remarks>
public sealed class CallerIdentity
{
    /// <summary>
    /// The subject - who is calling. Keyed on by the grant table of docs/DESIGN.md §6.5.4.
    /// </summary>
    /// <remarks>
    /// Written to the audit record as <c>sub</c>. Compared ordinally, never case-folded: an
    /// authorization server's subject identifier is an opaque string and two that differ only in
    /// case are two subjects.
    /// </remarks>
    public required string Subject { get; init; }

    /// <summary>
    /// Which client is calling, <strong>verbatim</strong>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Never normalized - not lowercased, not trimmed, not percent-decoded. This lands in the audit
    /// record as <c>client_id</c>, and a record is a statement about what happened. Normalizing it
    /// rewrites history into something that looks tidier and is no longer what the token said.
    /// </para>
    /// <para>
    /// The rule was learned in a different consumer of the same authorization server, where the
    /// client id is written into a trailer on every commit: normalizing it there would have
    /// silently re-attributed past work. Same rule, same reason, different record.
    /// </para>
    /// </remarks>
    public required string ClientId { get; init; }

    /// <summary>
    /// Which grant - the identifier that stays stable across a refresh. Written as <c>gid</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is what groups a run of commands into one working session, which is the thing dropping
    /// the session shell (docs/DESIGN.md §3.1) took away and this gives back.
    /// </para>
    /// <para>
    /// <strong>Not the token id.</strong> An access token identifier is minted fresh per token, so
    /// grouping by it splits one three-hour session into a new group at every refresh - exactly the
    /// grouping it was reached for to provide. The two are kept side by side because they answer
    /// different questions and are extremely easy to confuse.
    /// </para>
    /// </remarks>
    public required string GrantId { get; init; }

    /// <summary>
    /// Which token. Written as <c>jti</c>, kept so a revocation can be correlated to the calls the
    /// revoked token made.
    /// </summary>
    public required string TokenId { get; init; }

    /// <summary>
    /// What the token's scope claim said, if it said anything. Read together with
    /// <see cref="ScopeClaim" /> - never on its own.
    /// </summary>
    /// <remarks>
    /// Empty for both <see cref="ScopeClaimState.Absent" /> and
    /// <see cref="ScopeClaimState.Unreadable" />, which is precisely why the state is a separate
    /// property. Use <see cref="Grants" /> rather than reading this set directly.
    /// </remarks>
    public IReadOnlySet<string> Scopes { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// Whether <see cref="Scopes" /> is an answer at all.
    /// </summary>
    public required ScopeClaimState ScopeClaim { get; init; }

    /// <summary>
    /// Which authenticator produced this identity, for the audit record only.
    /// </summary>
    /// <remarks>
    /// Provenance, not a branch. Nothing in SshWarden outside the audit writer may read this to
    /// decide anything - docs/DESIGN.md §6.2 requires the rest of the code to be unable to tell which
    /// implementation is running. It exists because "which of the five values were derived rather
    /// than presented by an authorization server" is a question a reader of the log will have, and
    /// the alternative is inferring it from the shape of the other fields.
    /// </remarks>
    public required string Source { get; init; }

    /// <summary>
    /// Whether the token granted <paramref name="scope" />: <see langword="true" />,
    /// <see langword="false" />, or <see langword="null" /> when the token did not say.
    /// </summary>
    /// <returns>
    /// <see langword="true" /> or <see langword="false" /> when the scope claim was readable;
    /// <see langword="false" /> when it was present but unreadable; <see langword="null" /> when
    /// there was no claim, meaning the caller should fall back to the grant table.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The nullable return is the mechanism, not a convenience. <c>bool?</c> does not convert to
    /// <c>bool</c>, so <c>if (!identity.Grants("ssh:exec"))</c> does not compile and the third case
    /// cannot be folded into either of the other two by accident. A plain <c>bool</c> here would
    /// have to pick a side for "the token did not say", and either choice is wrong somewhere.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="scope" /> is null.</exception>
    public bool? Grants(string scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return ScopeClaim switch
        {
            ScopeClaimState.Readable => Scopes.Contains(scope),

            // Present and unparseable. Answering "no" rather than "did not say" is the whole point:
            // "did not say" sends the caller to the grant table, which is the fail-open.
            ScopeClaimState.Unreadable => false,

            // Absent, and Unknown - which means nobody filled this in. Both send the caller to the
            // grant table, and for Unknown that is the safe direction: the grant table is
            // deny-by-default, so an unset state grants nothing rather than everything.
            _ => null,
        };
    }
}
