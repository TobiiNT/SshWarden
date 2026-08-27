namespace SshWarden.Auth;

/// <summary>
/// Whether the caller's token said anything about scopes, and whether it could be read.
/// </summary>
/// <remarks>
/// <para>
/// Three values because two produce a fail-open, and the failure is silent.
/// </para>
/// <para>
/// A token with no <c>scope</c> claim and a token whose <c>scope</c> claim could not be parsed both
/// yield an empty scope set. They must not be treated alike: docs/DESIGN.md §6.5.4 falls back to the
/// grant table for the first (an authorization server that publishes no scopes, and every static
/// token, land there legitimately) and refuses the second. Collapse them and a token that was
/// written to grant nothing - or one mangled by a single character outside RFC 6749's scope-token
/// set - is widened into whatever the grant table allows. That is the dangerous direction.
/// </para>
/// <para>
/// The connector this design was checked against had already hit this and patched around it by
/// asking whether the raw claim collection contained the key before trusting the parsed set. Naming
/// the states makes that check part of the type rather than a habit.
/// </para>
/// </remarks>
public enum ScopeClaimState
{
    /// <summary>
    /// Nothing has been determined yet. The default, so a value-typed field that was never assigned
    /// grants nothing rather than accidentally reading as <see cref="Absent" />.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// The token carried no scope claim at all. Authority comes from the grant table alone.
    /// </summary>
    /// <remarks>
    /// This is the normal state for a static token, and for a token from an authorization server
    /// that does not publish scopes. It is not an error.
    /// </remarks>
    Absent = 1,

    /// <summary>
    /// The token carried a scope claim and it parsed. <see cref="CallerIdentity.Scopes" /> is what
    /// it said - possibly empty, which is a deliberate grant of nothing.
    /// </summary>
    Readable = 2,

    /// <summary>
    /// The token carried a scope claim that could not be parsed. Every scope question answers no.
    /// </summary>
    /// <remarks>
    /// Deliberately not the same as <see cref="Absent" />: falling back to the grant table here
    /// would let a malformed claim grant more than the token said.
    /// </remarks>
    Unreadable = 3,
}
