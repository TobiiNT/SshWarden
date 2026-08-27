using System.Security.Claims;

using SshWarden.Auth;
using SshWarden.Configuration;

namespace SshWarden.OAuth;

/// <summary>
/// Reads the five named values out of a token the bearer handler has already validated.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Validation happened before this runs and none of it happens here.</strong> The signature,
/// the issuer, the audience and the expiry are the bearer handler's, which answers 401 on its own;
/// arriving here means a token got past all of that. What is left is turning claims into the shape
/// the grant table, the gate and the audit record read - and refusing when a claim they need is not
/// there, rather than filling one in.
/// </para>
/// <para>
/// <strong>Which claims those are is configuration, not a constant.</strong> RFC 9068 names
/// <c>client_id</c> and <c>jti</c> for a JWT access token; nothing names the one that groups a
/// session, so <c>auth.oauth.grant_id_claim</c> exists and its documentation says what to do when an
/// authorization server emits nothing of the kind. A default that silently guessed would put a
/// column in the audit log that looks like it came from the authorization server and did not.
/// </para>
/// </remarks>
/// <param name="options">The <c>[auth.oauth]</c> table, for the claim names.</param>
public sealed class OAuthAuthenticator(OAuthSection options) : ISshWardenAuthenticator
{
    /// <summary>What the audit record calls this authenticator.</summary>
    /// <remarks>
    /// <c>oauth</c> rather than the name of any one authorization server. A record saying which
    /// vendor issued the token would be wrong the day the deployment moves, and the issuer is in
    /// the config file where it is true by construction.
    /// </remarks>
    public const string SourceName = "oauth";

    private readonly OAuthSection _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <inheritdoc />
    public string Name => SourceName;

    /// <inheritdoc />
    public ValueTask<AuthenticationResult> AuthenticateAsync(
        AuthenticationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Reaching past a validator that did not run is how a request carrying an unverified token
        // gets treated as verified. The bearer middleware answers 401 itself, so arriving here
        // without an authenticated principal means it was not in the pipeline - a wiring mistake,
        // and not something to guess around.
        if (request.Principal?.Identity?.IsAuthenticated != true)
        {
            return Refuse(
                "no_validated_token",
                "This request carried no validated access token. The bearer middleware runs before "
                    + "this and answers 401 on its own, so reaching here without one means it was "
                    + "not in the pipeline - not that the caller did anything wrong.");
        }

        var subject = Claim(request.Principal, ClaimTypes.NameIdentifier)
            ?? Claim(request.Principal, "sub");

        if (string.IsNullOrWhiteSpace(subject))
        {
            return Refuse(
                "token_without_subject",
                "The access token carries no 'sub'. That is the key the grant table is looked up "
                    + "by, so there is nothing to authorize against.");
        }

        foreach (var (claim, refusal) in new[]
        {
            (_options.ClientIdClaim, "client_id"),
            (_options.GrantIdClaim, "grant_id"),
            (_options.TokenIdClaim, "token_id"),
        })
        {
            if (string.IsNullOrWhiteSpace(Claim(request.Principal, claim)))
            {
                // Refused rather than filled in. A placeholder produces an audit record that looks
                // complete and answers nothing: the client id is what two records of one client
                // match on, the grant id is what groups a session across a refresh, and the token id
                // is what ties a revocation to the calls the revoked token made.
                return Refuse(
                    "token_without_" + refusal,
                    $"The access token carries no '{claim}', which auth.oauth.{refusal}_claim names. "
                        + "Either the authorization server does not emit it or it spells it "
                        + "differently; set that key to the claim it does emit. See its "
                        + "documentation for what to do when there is no such claim at all.");
            }
        }

        var scopeClaim = Claim(request.Principal, "scope");

        return ValueTask.FromResult(AuthenticationResult.Success(new CallerIdentity
        {
            Subject = subject,
            ClientId = Claim(request.Principal, _options.ClientIdClaim)!,
            GrantId = Claim(request.Principal, _options.GrantIdClaim)!,
            TokenId = Claim(request.Principal, _options.TokenIdClaim)!,
            Scopes = ParseScopes(scopeClaim),
            ScopeClaim = ReadScopeState(scopeClaim),
            Source = SourceName,
        }));
    }

    /// <summary>
    /// Which of the three states the <c>scope</c> claim is in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The distinction the grant table depends on. A token with no <c>scope</c> claim falls back to
    /// the grant table, because an authorization server that publishes no scopes issues tokens
    /// carrying none; a token with one that grants nothing is a token written to grant nothing and
    /// is refused. Collapsing the two grants <em>more</em> to a caller whose token was written to
    /// restrict them, with nothing failing anywhere.
    /// </para>
    /// <para>
    /// RFC 6749 §3.3 makes the claim a space-delimited list of scope-tokens, and §3.3's grammar
    /// excludes the double quote and the backslash. A claim carrying either is not a scope list this
    /// can read, and reading the part before the bad character would grant a caller some of a
    /// restriction that was written to be read whole.
    /// </para>
    /// </remarks>
    private static ScopeClaimState ReadScopeState(string? scope)
    {
        if (scope is null)
        {
            return ScopeClaimState.Absent;
        }

        return scope.Contains('"', StringComparison.Ordinal) || scope.Contains('\\', StringComparison.Ordinal)
            ? ScopeClaimState.Unreadable
            : ScopeClaimState.Readable;
    }

    private static HashSet<string> ParseScopes(string? scope)
        => ReadScopeState(scope) is ScopeClaimState.Readable && scope is not null
            ? new HashSet<string>(
                scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal);

    private static string? Claim(ClaimsPrincipal principal, string type)
        => principal.FindFirst(type)?.Value;

    private static ValueTask<AuthenticationResult> Refuse(string refusal, string detail)
        => ValueTask.FromResult(AuthenticationResult.Refuse(refusal, detail));
}
