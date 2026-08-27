using System.Security.Claims;

using SshWarden.Auth;
using SshWarden.Configuration;

using Xunit;

namespace SshWarden.OAuth.Tests;

/// <summary>
/// What the generic authenticator reads out of a token the bearer handler has already validated.
/// </summary>
/// <remarks>
/// Every refusal here has a sibling proving the same path accepts what it should. A test that only
/// asserts a refusal cannot tell a working rule from an authenticator that refuses everything.
/// </remarks>
public sealed class OAuthAuthenticatorTests
{
    private static readonly string[] Granted = ["ssh:exec", "ssh:read"];

    [Fact]
    public async Task It_fills_the_same_five_named_values_the_static_one_does()
    {
        // One set of named values, two implementations, and nothing downstream able to tell which
        // ran. The grant table, the gate and the audit record read these five and never ask where
        // they came from.
        var identity = (await Authenticate(Principal())).Identity;

        Assert.NotNull(identity);
        Assert.Equal("someone", identity.Subject);
        Assert.Equal("some-client", identity.ClientId);
        Assert.Equal("grant-7", identity.GrantId);
        Assert.Equal("token-9", identity.TokenId);
        Assert.Equal(OAuthAuthenticator.SourceName, identity.Source);
        Assert.Equal(ScopeClaimState.Readable, identity.ScopeClaim);
        Assert.Equal(Granted, identity.Scopes.OrderBy(scope => scope, StringComparer.Ordinal));
    }

    [Fact]
    public async Task The_claim_names_come_from_configuration()
    {
        // The whole reason this assembly exists beside the Boltway one. RFC 9068 names client_id and
        // jti; nothing names the one that groups a session, so an authorization server spelling them
        // differently is configuration rather than a fork.
        var options = Options("caller_id", "tid", "sid");

        var principal = Principal(claims:
        [
            new Claim("sub", "someone"),
            new Claim("caller_id", "some-client"),
            new Claim("sid", "session-7"),
            new Claim("tid", "token-9"),
        ]);

        var identity = (await Authenticate(principal, options)).Identity;

        Assert.NotNull(identity);
        Assert.Equal("some-client", identity.ClientId);
        Assert.Equal("session-7", identity.GrantId);
        Assert.Equal("token-9", identity.TokenId);
    }

    [Fact]
    public async Task A_request_nothing_validated_is_refused_rather_than_read()
    {
        // Reaching past a validator that did not run is how an unverified token gets treated as
        // verified. The bearer middleware answers 401 itself, so arriving here without a principal
        // means it was not in the pipeline.
        var result = await Authenticate(principal: null);

        Assert.False(result.IsAuthenticated);
        Assert.Equal("no_validated_token", result.Refusal);
    }

    [Fact]
    public async Task An_unauthenticated_principal_is_refused_too()
    {
        // Not the same as null, and the distinction is the trap: an empty ClaimsPrincipal is
        // non-null, so a check for null alone reads "nobody" as "somebody carrying no claims".
        var result = await Authenticate(new ClaimsPrincipal(new ClaimsIdentity()));

        Assert.False(result.IsAuthenticated);
        Assert.Equal("no_validated_token", result.Refusal);
    }

    [Fact]
    public async Task A_token_with_no_subject_is_refused_by_name()
    {
        var result = await Authenticate(Principal(drop: "sub"));

        Assert.False(result.IsAuthenticated);
        Assert.Equal("token_without_subject", result.Refusal);
    }

    [Theory]
    [InlineData("client_id", "token_without_client_id")]
    [InlineData("gid", "token_without_grant_id")]
    [InlineData("jti", "token_without_token_id")]
    public async Task A_token_missing_a_value_the_record_needs_is_refused_rather_than_filled_in(
        string claim,
        string refusal)
    {
        // A placeholder would produce a record that looks complete and answers nothing. The detail
        // names the config key, because the fix is usually that the authorization server spells the
        // claim differently rather than that it is missing.
        var result = await Authenticate(Principal(drop: claim));

        Assert.False(result.IsAuthenticated);
        Assert.Equal(refusal, result.Refusal);
        Assert.Contains(claim, result.Detail!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ssh:read ssh:exec", ScopeClaimState.Readable)]
    [InlineData("ssh:read \"quoted\"", ScopeClaimState.Unreadable)]
    public async Task A_scope_claim_that_is_there_is_read_and_its_readability_kept(
        string scope,
        ScopeClaimState expected)
    {
        var result = await Authenticate(Principal(scope: scope));

        Assert.Equal(expected, result.Identity!.ScopeClaim);
    }

    [Fact]
    public async Task A_token_with_no_scope_claim_says_absent_rather_than_empty()
    {
        // The state that matters most: absent means fall back to the grant table, because an
        // authorization server publishing no scopes issues tokens carrying none. Reading it as
        // "granted nothing" would refuse every caller of such a deployment.
        var result = await Authenticate(Principal(scope: null));

        Assert.Equal(ScopeClaimState.Absent, result.Identity!.ScopeClaim);
        Assert.Empty(result.Identity.Scopes);
    }

    [Fact]
    public async Task An_unreadable_scope_claim_carries_no_scopes()
    {
        // The half that is a security property rather than a nicety. A claim rejected is rejected
        // whole: keeping whatever parsed before the bad character would grant a caller part of a
        // restriction written to be read entirely or not at all.
        var result = await Authenticate(Principal(scope: "ssh:read \"quoted\""));

        Assert.Empty(result.Identity!.Scopes);
    }

    private static async Task<AuthenticationResult> Authenticate(
        ClaimsPrincipal? principal,
        OAuthSection? options = null)
        => await new OAuthAuthenticator(options ?? Options()).AuthenticateAsync(
            new AuthenticationRequest { Principal = principal },
            CancellationToken.None);

    private static OAuthSection Options(
        string clientId = "client_id",
        string tokenId = "jti",
        string grantId = "gid")
        => new()
        {
            Issuer = "https://auth.example.com",
            Resource = "https://sshwarden.example.com/mcp",
            ClientIdClaim = clientId,
            TokenIdClaim = tokenId,
            GrantIdClaim = grantId,
        };

    /// <summary>A principal shaped like one the bearer handler produces.</summary>
    private static ClaimsPrincipal Principal(
        string? drop = null,
        string? scope = "ssh:read ssh:exec",
        IReadOnlyList<Claim>? claims = null)
    {
        var built = claims?.ToList() ??
        [
            new Claim("sub", "someone"),
            new Claim("client_id", "some-client"),
            new Claim("gid", "grant-7"),
            new Claim("jti", "token-9"),
        ];

        if (scope is not null && claims is null)
        {
            built.Add(new Claim("scope", scope));
        }

        if (drop is not null)
        {
            built.RemoveAll(claim => claim.Type == drop);
        }

        // An authentication type, because ClaimsIdentity reports IsAuthenticated only when it has
        // one - which is exactly what tells this authenticator a validator actually ran.
        return new ClaimsPrincipal(new ClaimsIdentity(built, "Bearer"));
    }
}
