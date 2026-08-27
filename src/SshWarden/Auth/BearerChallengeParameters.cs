namespace SshWarden.Auth;

/// <summary>
/// What this deployment's <c>401</c> challenge carries beyond the scheme name.
/// </summary>
/// <remarks>
/// <para>
/// A challenge is the only thing a client that has never seen this server gets to read. RFC 6750 §3
/// gives it the scheme and an error; RFC 9728 §5.1 adds <c>resource_metadata</c>, which is the
/// pointer to the document naming where to authenticate. Without that pointer the discovery chain
/// has no first link: the server publishes a perfectly good metadata document and nothing tells a
/// client it is there.
/// </para>
/// <para>
/// <strong>Here rather than in the middleware, because the middleware must not know how the
/// deployment authenticates.</strong> <c>SshWarden.Mcp</c> answers "is there a caller at all" for
/// every mode, and static-token mode has no metadata document and no scopes - so the values come
/// from whichever assembly wired the mode, and this type is the shape they arrive in.
/// </para>
/// <para>
/// A <c>TryAdd</c> seam like every other: <c>AddSshWarden</c> registers <see cref="None" />, so a
/// mode that fills this registers <strong>before</strong> that call and wins. Registering after it
/// silently does nothing, which is the failure this repository's other seams share and warn about
/// in the same words.
/// </para>
/// </remarks>
public sealed class BearerChallengeParameters
{
    /// <summary>A challenge with nothing to add - the scheme, and an error when there is one.</summary>
    /// <remarks>
    /// What static-token mode uses. There is no metadata document to point at and no scope
    /// vocabulary to name, and inventing either would be advertising a capability that is not there.
    /// </remarks>
    public static BearerChallengeParameters None { get; } = new();

    /// <summary>The absolute URL of this resource's RFC 9728 metadata document, or null.</summary>
    /// <remarks>
    /// Absolute, because §5.1's example is and because a client is entitled to treat it as a URL it
    /// can fetch without knowing which origin the challenge came from.
    /// </remarks>
    public string? ResourceMetadata { get; init; }

    /// <summary>
    /// Every scope this deployment supports. Never a subset, and never the endpoint's own.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>This is the parameter that cost six and a half hours.</strong> A connector built on
    /// the same authorization server filled it from an endpoint-level scope requirement, so every
    /// client was told to ask for only the scope named there; the scope it did not name was never
    /// granted to anybody, and every operation needing it failed until somebody read a token.
    /// docs/DESIGN.md §6.5.0 has the account.
    /// </para>
    /// <para>
    /// One MCP endpoint carries every tool here, so there is no per-endpoint requirement to narrow
    /// this to even if narrowing were safe. The value is the same list the metadata document
    /// publishes, from the same configured field, for exactly that reason.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> ScopesSupported { get; init; } = [];

    /// <summary>Builds the <c>WWW-Authenticate</c> value for a refusal.</summary>
    /// <param name="credentialWasSent">
    /// Whether the request carried a credential at all. RFC 6750 §3.1: a request that sent none gets
    /// no <c>error</c>, because there is nothing to report about a token that was never sent - the
    /// client's next step is to acquire one, not to conclude the one it holds is bad.
    /// </param>
    /// <returns>The header value, always beginning with <c>Bearer</c>.</returns>
    /// <remarks>
    /// <para>
    /// Assembled here rather than at each call site so the quoting is written once. RFC 6750 §3
    /// quotes every parameter value, and a value that reached this header unquoted would end the
    /// parameter list early at the next comma - which a client reads as a challenge missing
    /// everything after it.
    /// </para>
    /// <para>
    /// Nothing is escaped, and the reason is that nothing reaching here can need it: the
    /// configuration loader refuses a scope outside RFC 6749 §3.3's <c>scope-token</c> set and a
    /// resource identifier carrying a quote or a backslash, naming both at the file rather than
    /// letting either arrive at this header. Escaping here instead would move the boundary to the
    /// one place an operator cannot see it.
    /// </para>
    /// </remarks>
    public string Header(bool credentialWasSent)
    {
        var parameters = new List<string>(3);

        if (credentialWasSent)
        {
            parameters.Add("error=\"invalid_token\"");
        }

        if (ResourceMetadata is { Length: > 0 } metadata)
        {
            parameters.Add($"resource_metadata=\"{metadata}\"");
        }

        if (ScopesSupported.Count > 0)
        {
            parameters.Add($"scope=\"{string.Join(' ', ScopesSupported)}\"");
        }

        return parameters.Count == 0 ? "Bearer" : "Bearer " + string.Join(", ", parameters);
    }
}
