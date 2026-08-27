using System.Security.Claims;

using SshWarden.Auth;

using Xunit;

namespace SshWarden.Boltway.Tests;

/// <summary>
/// What the second authenticator reads out of a token Boltway has already validated.
/// </summary>
/// <remarks>
/// Every refusal here has a sibling proving the same path accepts what it should. A test that only
/// asserts a refusal cannot tell a working rule from an authenticator that refuses everything.
/// </remarks>
public sealed class BoltwayAuthenticatorTests
{
    private static readonly string[] Granted = ["ssh:exec", "ssh:read"];

    [Fact]
    public async Task It_fills_the_same_five_named_values_the_static_one_does()
    {
        // The contract docs/DESIGN.md §6.2 sets: two implementations, one set of named values,
        // and nothing downstream able to tell which ran. The grant table, the gate and the audit
        // record read these five and never ask where they came from.
        var result = await Authenticate(Principal());

        var identity = result.Identity;
        Assert.NotNull(identity);

        Assert.Equal("someone", identity.Subject);
        Assert.Equal("claude-code", identity.ClientId);
        Assert.Equal("bw_grant_7", identity.GrantId);
        Assert.Equal("bw_jti_9", identity.TokenId);
        Assert.Equal(BoltwayAuthenticator.SourceName, identity.Source);
        Assert.Equal(ScopeClaimState.Readable, identity.ScopeClaim);
        Assert.Equal(Granted, identity.Scopes.OrderBy(scope => scope, StringComparer.Ordinal));
    }

    [Fact]
    public async Task The_subject_is_sub_and_not_a_name_somebody_can_change()
    {
        // Boltway's own mapper prefers `preferred_username` for its Actor, which is right for
        // something a person reads. This is the key the grant table is looked up by, and a display
        // name is mutable: a rule granting production access would follow a rename, or stop
        // matching one.
        var result = await Authenticate(Principal(extra: ("preferred_username", "somebody-else")));

        Assert.Equal("someone", result.Identity!.Subject);
    }

    [Theory]
    [InlineData("ssh:read ssh:exec", ScopeClaimState.Readable)]
    [InlineData("ssh:read \"quoted\"", ScopeClaimState.Unreadable)]
    public async Task A_scope_claim_that_is_there_is_read_and_its_readability_kept(
        string scope,
        ScopeClaimState expected)
    {
        // Three states, and this is the whole reason the pinned version is 0.3.0. A claim that
        // granted nothing, a claim that could not be parsed and no claim at all all produce an empty
        // set, and only here is the difference still known.
        var result = await Authenticate(Principal(scope: scope));

        Assert.Equal(expected, result.Identity!.ScopeClaim);
    }

    [Fact]
    public async Task A_token_with_no_scope_claim_says_absent_rather_than_empty()
    {
        // The state that matters most: absent means fall back to the grant table, because an
        // authorization server that publishes no scopes issues tokens carrying none. Reading it as
        // "granted nothing" would refuse every caller of such a deployment.
        var result = await Authenticate(Principal(scope: null));

        Assert.Equal(ScopeClaimState.Absent, result.Identity!.ScopeClaim);
        Assert.Empty(result.Identity.Scopes);
    }

    [Fact]
    public async Task An_unreadable_scope_claim_carries_no_scopes()
    {
        // The half that is a security property rather than a nicety. A claim `ScopeSet` rejected is
        // rejected whole, so keeping whatever parsed before the bad character would grant a caller
        // part of a restriction that was written to be read entirely or not at all.
        var result = await Authenticate(Principal(scope: "ssh:read \"quoted\""));

        Assert.Empty(result.Identity!.Scopes);
    }

    [Fact]
    public async Task A_request_nothing_validated_is_refused_rather_than_read()
    {
        // The seam's own contract: reaching past a validator that did not run is how a request
        // carrying an unverified token gets treated as verified. Boltway's middleware answers 401
        // itself, so arriving here without a principal means it was not in the pipeline.
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
    [InlineData("client_id")]
    [InlineData("gid")]
    [InlineData("jti")]
    public async Task A_token_missing_a_value_the_record_needs_is_refused_rather_than_filled_in(string claim)
    {
        // A placeholder would produce a record that looks complete and answers nothing: `client_id`
        // is what two records of one client match on, `gid` is what groups a session across a
        // refresh, `jti` is what ties a revocation to the calls the revoked token made.
        var result = await Authenticate(Principal(drop: claim));

        Assert.False(result.IsAuthenticated);
        Assert.Equal("token_without_" + claim, result.Refusal);
        Assert.Contains(claim, result.Detail!, StringComparison.Ordinal);
    }

    private static async Task<AuthenticationResult> Authenticate(ClaimsPrincipal? principal)
        => await new BoltwayAuthenticator().AuthenticateAsync(
            new AuthenticationRequest { Principal = principal },
            CancellationToken.None);

    /// <summary>A principal shaped like one Boltway's bearer middleware produces.</summary>
    /// <param name="drop">A claim to leave out, for the refusal cases.</param>
    /// <param name="scope">The scope claim, or null to leave it out entirely.</param>
    /// <param name="extra">Anything else to add.</param>
    private static ClaimsPrincipal Principal(
        string? drop = null,
        string? scope = "ssh:read ssh:exec",
        (string Type, string Value)? extra = null)
    {
        var claims = new List<Claim>
        {
            new("sub", "someone"),
            new("client_id", "claude-code"),
            new("gid", "bw_grant_7"),
            new("jti", "bw_jti_9"),
        };

        if (scope is not null)
        {
            claims.Add(new Claim("scope", scope));
        }

        if (extra is { } pair)
        {
            claims.Add(new Claim(pair.Type, pair.Value));
        }

        if (drop is not null)
        {
            claims.RemoveAll(claim => claim.Type == drop);
        }

        // An authentication type, because ClaimsIdentity reports IsAuthenticated only when it has
        // one - which is exactly what tells this authenticator a validator actually ran.
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
    }
}
