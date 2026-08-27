using SshWarden.Auth;
using SshWarden.Configuration;

using Xunit;

namespace SshWarden.Tests;

public sealed class StaticTokenAuthenticatorTests
{
    private const string LaptopToken = "0123456789012345678901234567890123456789";
    private const string CiToken = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn";

    [Fact]
    public async Task The_configured_credential_authenticates()
    {
        var result = await Authenticate("Bearer " + LaptopToken);

        Assert.True(result.IsAuthenticated);
        Assert.Equal("someone", result.Identity!.Subject);
        Assert.Equal(StaticTokenAuthenticator.SourceName, result.Identity.Source);
    }

    [Fact]
    public async Task All_five_identity_values_are_filled()
    {
        // The audit record of docs/DESIGN.md §4.2 carries all five, and a record with a hole in it is
        // the failure the whole project exists to avoid. "The static implementation has no grant"
        // is not an excuse for a null here - it is a reason to say what a grant means for one.
        var identity = (await Authenticate("Bearer " + LaptopToken)).Identity!;

        Assert.False(string.IsNullOrEmpty(identity.Subject));
        Assert.False(string.IsNullOrEmpty(identity.ClientId));
        Assert.False(string.IsNullOrEmpty(identity.GrantId));
        Assert.False(string.IsNullOrEmpty(identity.TokenId));
        Assert.Equal(ScopeClaimState.Absent, identity.ScopeClaim);
    }

    [Fact]
    public async Task A_static_token_carries_no_scope_claim()
    {
        // Absent, not Unreadable and not an empty Readable: the token said nothing about scopes, so
        // authority comes from the grant table. Grants() returning null is what routes it there.
        var identity = (await Authenticate("Bearer " + LaptopToken)).Identity!;

        Assert.Equal(ScopeClaimState.Absent, identity.ScopeClaim);
        Assert.Null(identity.Grants("ssh:read"));
    }

    [Fact]
    public async Task The_grant_id_and_the_token_id_are_not_the_same_value()
    {
        // They answer different questions and are extremely easy to confuse - an earlier draft of
        // this design grouped sessions by the token id, which splits one working session into a new
        // group at every refresh. Keeping them distinct here keeps the two columns meaning two
        // things even in the deployment that has no refreshes to tell them apart.
        var identity = (await Authenticate("Bearer " + LaptopToken)).Identity!;

        Assert.NotEqual(identity.GrantId, identity.TokenId);
    }

    [Fact]
    public async Task Two_credentials_get_different_grant_ids()
    {
        var laptop = (await Authenticate("Bearer " + LaptopToken)).Identity!;
        var ci = (await Authenticate("Bearer " + CiToken)).Identity!;

        Assert.NotEqual(laptop.GrantId, ci.GrantId);
    }

    [Fact]
    public async Task The_client_id_defaults_to_the_token_name()
    {
        var identity = (await Authenticate("Bearer " + LaptopToken)).Identity!;

        Assert.Equal("laptop", identity.ClientId);
    }

    [Fact]
    public async Task An_explicit_client_id_is_kept_verbatim()
    {
        // Not lowercased, not trimmed. This lands in the audit record, and a record is a statement
        // about what happened; normalizing it rewrites history into something tidier that is no
        // longer what was configured.
        var identity = (await Authenticate("Bearer " + CiToken)).Identity!;

        Assert.Equal("  Claude-Desktop  ", identity.ClientId);
    }

    [Fact]
    public async Task A_credential_that_matches_nothing_is_refused_without_quoting_it()
    {
        const string Guess = "wrong-token-wrong-token-wrong-token-wrong";

        var result = await Authenticate("Bearer " + Guess);

        Assert.False(result.IsAuthenticated);
        Assert.Equal(AuthenticationRefusal.UnknownCredential, result.Refusal);

        // The detail reaches the operator's log. It must not carry the credential, or any part of
        // it, and must not say whether the guess was close - which is what a per-entry message
        // would say to somebody enumerating.
        Assert.DoesNotContain(Guess, result.Detail!, StringComparison.Ordinal);
        Assert.DoesNotContain("laptop", result.Detail!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task No_header_is_refused_as_no_credential_rather_than_a_bad_one()
    {
        var result = await Authenticate(header: null);

        // The distinction a client acts on: acquire a credential, rather than conclude the one it
        // holds is bad.
        Assert.Equal(AuthenticationRefusal.NoCredential, result.Refusal);
    }

    [Theory]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Bearer")]
    [InlineData("Bearer   ")]
    [InlineData("Bearer0123456789012345678901234567890123456789")]
    public async Task A_header_that_is_not_a_bearer_credential_is_refused(string header)
    {
        var result = await Authenticate(header);

        Assert.Equal(AuthenticationRefusal.MalformedHeader, result.Refusal);
    }

    [Theory]
    [InlineData("bearer ")]
    [InlineData("BEARER ")]
    [InlineData("  Bearer  ")]
    public async Task The_scheme_is_case_insensitive_and_surrounded_by_optional_whitespace(string prefix)
    {
        // RFC 7235 §2.1 makes the scheme case-insensitive and RFC 9110 §5.5 makes the surrounding
        // whitespace not part of the value. The control for the refusals above: without it, a
        // parser that rejected everything would look like a working one.
        var result = await Authenticate(prefix + LaptopToken);

        Assert.True(result.IsAuthenticated);
    }

    [Fact]
    public void An_authenticator_with_no_credentials_is_refused_at_construction()
    {
        // Not merely useless. An authenticator that can authenticate nobody looks, at every call
        // site downstream, exactly like one that is working and being given wrong credentials.
        Assert.Throws<ArgumentException>(() => new StaticTokenAuthenticator([]));
    }

    private static async Task<AuthenticationResult> Authenticate(string? header)
    {
        var authenticator = new StaticTokenAuthenticator([
            new StaticTokenEntry { Name = "laptop", Subject = "someone", Token = LaptopToken },
            new StaticTokenEntry
            {
                Name = "ci",
                Subject = "someone",
                Token = CiToken,
                ClientId = "  Claude-Desktop  ",
            },
        ]);

        return await authenticator.AuthenticateAsync(
            new AuthenticationRequest { AuthorizationHeader = header },
            CancellationToken.None);
    }
}
