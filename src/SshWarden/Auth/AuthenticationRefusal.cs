namespace SshWarden.Auth;

/// <summary>
/// The stable identifiers an <see cref="ISshWardenAuthenticator" /> refuses under.
/// </summary>
/// <remarks>
/// <para>
/// Identifiers rather than sentences, for the same reason the audit record's <c>denied_by</c> is a
/// rule id: a message is prose somebody will improve, and every dashboard filtering on it breaks
/// silently when they do. These are matched character-for-character, so they are ASCII, lower
/// snake case, and English - like a scope name or a header field, not like page text.
/// </para>
/// <para>
/// They also never reach the caller. A client gets a bearer challenge and nothing else; which of
/// these fired is for the operator reading the server log, because the difference between
/// <see cref="UnknownCredential" /> and <see cref="MalformedHeader" /> is exactly the information
/// that turns guessing a token into checking one.
/// </para>
/// </remarks>
public static class AuthenticationRefusal
{
    /// <summary>No <c>Authorization</c> header was sent at all.</summary>
    public const string NoCredential = "no_credential";

    /// <summary>
    /// An <c>Authorization</c> header was sent but is not a well-formed bearer credential.
    /// </summary>
    public const string MalformedHeader = "malformed_header";

    /// <summary>
    /// A well-formed bearer credential that matches nothing this authenticator knows.
    /// </summary>
    /// <remarks>
    /// Deliberately one value covering "no such token" and "wrong token": an authenticator that
    /// distinguished them would be answering, to an unauthenticated caller, whether a guess was
    /// close.
    /// </remarks>
    public const string UnknownCredential = "unknown_credential";

    /// <summary>
    /// The credential was recognised but is no longer usable - expired, revoked, or withdrawn.
    /// </summary>
    /// <remarks>
    /// Unused by the static-token authenticator, which has no expiry to check. It exists here
    /// rather than being added later because the identifier is part of what an operator's log
    /// queries match on, and a value that appears for the first time in a later release is a query
    /// that quietly matched nothing until then.
    /// </remarks>
    public const string ExpiredCredential = "expired_credential";
}
