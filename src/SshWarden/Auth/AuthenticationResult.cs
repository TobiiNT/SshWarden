namespace SshWarden.Auth;

/// <summary>
/// The outcome of authenticating one request: an identity, or a refusal that names its boundary.
/// </summary>
/// <remarks>
/// A result type rather than a nullable <see cref="CallerIdentity" /> because a null answers "who"
/// with silence. Every refusal here carries which rule refused and enough detail for the operator
/// to act on it, and neither half is optional.
/// </remarks>
public sealed class AuthenticationResult
{
    private AuthenticationResult(CallerIdentity? identity, string? refusal, string? detail)
    {
        Identity = identity;
        Refusal = refusal;
        Detail = detail;
    }

    /// <summary>The caller, when authentication succeeded; otherwise <see langword="null" />.</summary>
    public CallerIdentity? Identity { get; }

    /// <summary>
    /// Which rule refused, as one of the <see cref="AuthenticationRefusal" /> identifiers;
    /// <see langword="null" /> when authentication succeeded.
    /// </summary>
    public string? Refusal { get; }

    /// <summary>
    /// What the operator needs to know about the refusal. <strong>Never returned to the caller.</strong>
    /// </summary>
    /// <remarks>
    /// This may name the header that was malformed or the shape that was expected. It must never
    /// contain the credential itself, or any prefix of it: a log line is read by more people than a
    /// config file, and a partial secret in one is a whole secret to someone who can guess the rest.
    /// </remarks>
    public string? Detail { get; }

    /// <summary>Whether a caller was established.</summary>
    /// <remarks>
    /// Written so that <see cref="Identity" /> is known non-null to the compiler on the true branch,
    /// which is what stops a refusal from being read as an anonymous-but-allowed caller.
    /// </remarks>
    public bool IsAuthenticated => Identity is not null;

    /// <summary>Authentication succeeded.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="identity" /> is null.</exception>
    public static AuthenticationResult Success(CallerIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return new AuthenticationResult(identity, refusal: null, detail: null);
    }

    /// <summary>Authentication was refused.</summary>
    /// <param name="refusal">One of the <see cref="AuthenticationRefusal" /> identifiers.</param>
    /// <param name="detail">What the operator needs, carrying no part of the credential.</param>
    /// <exception cref="ArgumentException"><paramref name="refusal" /> is null or whitespace.</exception>
    /// <exception cref="ArgumentException"><paramref name="detail" /> is null or whitespace.</exception>
    public static AuthenticationResult Refuse(string refusal, string detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refusal);

        // Required rather than optional. A refusal with no detail is the empty result this whole
        // type exists to prevent, one level in: the operator sees that something was refused and
        // has to reproduce it to find out what.
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);

        return new AuthenticationResult(identity: null, refusal, detail);
    }
}
