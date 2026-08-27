using SshWarden.Auth;

using Xunit;

namespace SshWarden.Tests;

public sealed class CallerIdentityTests
{
    [Fact]
    public void A_readable_claim_answers_yes_for_a_scope_it_carries()
    {
        var identity = Identity(ScopeClaimState.Readable, "ssh:read");

        Assert.True(identity.Grants("ssh:read"));
    }

    [Fact]
    public void A_readable_claim_answers_no_for_a_scope_it_does_not_carry()
    {
        var identity = Identity(ScopeClaimState.Readable, "ssh:read");

        Assert.False(identity.Grants("ssh:exec"));
    }

    [Fact]
    public void A_readable_but_empty_claim_answers_no()
    {
        // A token written to grant nothing. It is not the same as a token that said nothing, and
        // treating it as such would widen it to whatever the grant table allows.
        var identity = Identity(ScopeClaimState.Readable);

        Assert.False(identity.Grants("ssh:read"));
    }

    [Fact]
    public void An_absent_claim_answers_null()
    {
        // Null means "the token did not say", which sends the caller to the grant table. This is
        // the state a static token and an authorization server that publishes no scopes both land
        // in, and it is legitimate.
        var identity = Identity(ScopeClaimState.Absent);

        Assert.Null(identity.Grants("ssh:read"));
    }

    [Fact]
    public void An_unreadable_claim_answers_no_rather_than_null()
    {
        // The fail-open this whole three-state design exists to close. A scope claim rejected whole
        // for one character outside RFC 6749's set produces the same empty set as no claim at all;
        // if that answered "did not say", a mangled token would fall back to the grant table and be
        // granted more than it asked for. Flip this to Null and the enum has no reason to exist.
        var identity = Identity(ScopeClaimState.Unreadable, "ssh:read");

        Assert.False(identity.Grants("ssh:read"));
    }

    [Fact]
    public void An_unset_state_answers_null_rather_than_granting()
    {
        // Unknown is the default of the enum, so this is what a value nobody filled in does. Null
        // sends it to the deny-by-default grant table, which is the safe direction for a field that
        // was forgotten.
        var identity = Identity(ScopeClaimState.Unknown, "ssh:read");

        Assert.Null(identity.Grants("ssh:read"));
    }

    private static CallerIdentity Identity(ScopeClaimState state, params string[] scopes)
        => new()
        {
            Subject = "someone",
            ClientId = "a-client",
            GrantId = "a-grant",
            TokenId = "a-token",
            Source = "test",
            ScopeClaim = state,
            Scopes = new HashSet<string>(scopes, StringComparer.Ordinal),
        };
}
