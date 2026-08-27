namespace SshWarden.Auth;

/// <summary>
/// Pulls the credential out of an <c>Authorization</c> header, per RFC 6750 §2.1.
/// </summary>
/// <remarks>
/// One implementation shared by every authenticator. Two of them parsing the same header in two
/// slightly different ways is how a credential comes to be accepted by one and rejected by the
/// other, and the difference only ever shows up under a config change nobody connected to it.
/// </remarks>
public static class BearerCredential
{
    private const string Scheme = "Bearer";

    /// <summary>
    /// Extracts the bearer credential, or says which rule the header failed.
    /// </summary>
    /// <param name="headerValue">The raw header value, or <see langword="null" /> if absent.</param>
    /// <param name="credential">The credential, when this returns <see langword="true" />.</param>
    /// <param name="refusal">
    /// One of the <see cref="AuthenticationRefusal" /> identifiers, when this returns
    /// <see langword="false" />.
    /// </param>
    /// <returns>Whether a bearer credential was present and well-formed.</returns>
    public static bool TryParse(
        string? headerValue,
        out string credential,
        out string refusal)
    {
        credential = string.Empty;

        if (string.IsNullOrWhiteSpace(headerValue))
        {
            refusal = AuthenticationRefusal.NoCredential;
            return false;
        }

        // RFC 9110 §5.5 defines a field value as having optional leading and trailing whitespace
        // that is not part of the value, so stripping it here matches what every other participant
        // considers the header to say. Nothing inside the value is touched.
        var value = headerValue.Trim();

        // RFC 7235 §2.1 makes auth-scheme case-insensitive, so "bearer" and "BEARER" are the same
        // scheme. Ordinal-ignore-case rather than culture-aware: this is a protocol token, and the
        // Turkish dotless i is a real way for a culture-aware comparison to disagree with every
        // other implementation on the wire about whether "BEARER" starts with "Bear".
        if (!value.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            refusal = AuthenticationRefusal.MalformedHeader;
            return false;
        }

        var remainder = value[Scheme.Length..];

        // A scheme must be followed by whitespace, not run straight into the credential.
        // "Bearerfoo" is not a bearer credential and must not be read as one.
        if (remainder.Length == 0 || !char.IsWhiteSpace(remainder[0]))
        {
            refusal = AuthenticationRefusal.MalformedHeader;
            return false;
        }

        var token = remainder.TrimStart();
        if (token.Length == 0)
        {
            refusal = AuthenticationRefusal.MalformedHeader;
            return false;
        }

        // Nothing further is stripped and nothing is unescaped: past the scheme and its separator,
        // the credential is whatever the client sent. Normalizing it here would mean this and
        // whoever issued it disagree about what the token is.
        credential = token;
        refusal = string.Empty;
        return true;
    }
}
