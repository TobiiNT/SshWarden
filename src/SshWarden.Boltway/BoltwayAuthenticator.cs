using System.Security.Claims;

using Boltway.OAuth.Primitives.Scopes;

using SshWarden.Auth;

namespace SshWarden.Boltway;

/// <summary>Reads the identity out of an access token Boltway has already validated.</summary>
/// <remarks>
/// <para>
/// The second implementation docs/DESIGN.md §6.2 requires, and it fills the same five named
/// values the static one does - subject, client id, grant id, token id, scope claim - so nothing
/// downstream can tell which is running. That is the whole contract: the grant table, the gate and
/// the audit record read <see cref="CallerIdentity" /> and never ask where it came from.
/// </para>
/// <para>
/// <strong>It validates nothing.</strong> The signature, the issuer, the audience and the expiry are
/// checked by Boltway's bearer middleware, which runs first and answers 401 itself; this reads the
/// principal that check produced. Splitting it that way is deliberate - the validator is
/// <c>internal</c> to Boltway.ResourceServer, and reimplementing JWT validation here to keep it in
/// one class would be hand-rolling the one part of this that must not be hand-rolled.
/// </para>
/// <para>
/// So a null principal is refused rather than worked around, exactly as
/// <see cref="AuthenticationRequest.Principal" /> says: reaching past a validator that did not run
/// is how a request carrying an unverified token gets treated as verified.
/// </para>
/// </remarks>
public sealed class BoltwayAuthenticator : ISshWardenAuthenticator
{
    /// <summary>What the audit record calls this implementation.</summary>
    public const string SourceName = "boltway";

    /// <inheritdoc />
    public string Name => SourceName;

    /// <inheritdoc />
    public ValueTask<AuthenticationResult> AuthenticateAsync(
        AuthenticationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Principal?.Identity?.IsAuthenticated != true)
        {
            return ValueTask.FromResult(AuthenticationResult.Refuse(
                "no_validated_token",
                "This request carried no validated access token. Boltway's bearer middleware runs "
                    + "before this and answers 401 on its own, so reaching here without one means "
                    + "it was not in the pipeline - not that the caller did anything wrong."));
        }

        // `sub`, and deliberately not `preferred_username`. Boltway's own ResourceServerAuthenticator
        // prefers the username for its Actor, which is right for something a person reads; this is
        // the key the grant table is looked up by, and a display name is a mutable string that an
        // authorization server may let its user change. A rule granting production access would then
        // follow a rename, or stop matching one.
        var subject = Claim(request.Principal, "sub");

        if (string.IsNullOrWhiteSpace(subject))
        {
            // Not a challenge, and not a 500 either. A token that validated and carries no `sub` is
            // the authorization server breaking its contract with this one, and telling the caller
            // to sign in again would send them to fix something re-authenticating cannot touch.
            return ValueTask.FromResult(AuthenticationResult.Refuse(
                "token_without_subject",
                "The access token validated and carries no 'sub', so there is nobody to attribute "
                    + "this call to. The authorization server has to put an identifier in the token."));
        }

        // Three states, not two, and this is the whole reason the pinned version is 0.3.0. A claim
        // that granted nothing, a claim that could not be parsed and no claim at all all produce an
        // empty set, and only here is the difference still known - the grant table refuses the
        // middle case and falls back for the last one.
        var raw = Claim(request.Principal, "scope");
        var readable = ScopeSet.TryParse(raw, out var parsed, out _);

        var state = raw is null
            ? ScopeClaimState.Absent
            : readable ? ScopeClaimState.Readable : ScopeClaimState.Unreadable;

        // Refused rather than filled in with a placeholder, and that is a decision. Every one of
        // these three has a job in the audit record that a stand-in defeats: `client_id` is what two
        // records of one client match on, `gid` is what groups a session across a refresh, `jti` is
        // what ties a revocation to the calls the revoked token made. Writing "unknown" into any of
        // them produces a record that looks complete and answers none of those questions.
        //
        // The authorization server this integrates with mints all three on every access token, so
        // an absence means the token came from one that does not - which an operator needs told by
        // name rather than left to discover from a dashboard that will not group.
        foreach (var required in new[] { "client_id", "gid", "jti" })
        {
            if (Claim(request.Principal, required) is null)
            {
                return ValueTask.FromResult(AuthenticationResult.Refuse(
                    "token_without_" + required,
                    $"The access token validated and carries no '{required}'. SshWarden records it "
                        + "on every call, and a placeholder would produce an audit record that looks "
                        + "complete and cannot be grouped or correlated. The authorization server "
                        + "has to put it in the token."));
            }
        }

        return ValueTask.FromResult(AuthenticationResult.Success(new CallerIdentity
        {
            Subject = subject,
            Source = SourceName,

            // Verbatim. It is an identifier a client chose, it reaches the audit record, and
            // normalising it here would make two records of the same client fail to match.
            ClientId = Claim(request.Principal, "client_id")!,

            // `gid`, not `jti`. docs/DESIGN.md §4.2: `jti` is minted fresh for every token, so
            // grouping a session by it breaks at the first refresh; `gid` is the grant and is stable
            // across the whole refresh family. Both are recorded - they answer different questions.
            GrantId = Claim(request.Principal, "gid")!,
            TokenId = Claim(request.Principal, "jti")!,

            ScopeClaim = state,
            Scopes = readable
                ? new HashSet<string>(parsed.Values, StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal),
        }));
    }

    /// <summary>The first value of a claim, or null when the token carries none.</summary>
    /// <remarks>
    /// First rather than every value, and that is right for these five: each is a single-valued
    /// registered claim. It would be wrong for a role or a scope array, which is why the scope claim
    /// above goes through <see cref="ScopeSet" /> instead of being read here.
    /// </remarks>
    private static string? Claim(ClaimsPrincipal principal, string type)
    {
        var value = principal.FindFirst(type)?.Value;
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
