using SshWarden.Auth;

using Xunit;

namespace SshWarden.Tests;

/// <summary>
/// What a client reads when it is refused.
/// </summary>
/// <remarks>
/// A challenge is the only thing a client that has never seen this server gets, so every rule about
/// its shape is a rule about whether discovery can start at all. These assert the header rather than
/// the pipeline; the pipeline is covered by the RFC 9728 contract each OAuth suite derives.
/// </remarks>
public sealed class BearerChallengeTests
{
    private static readonly BearerChallengeParameters Configured = new()
    {
        ResourceMetadata = "https://sshwarden.example/.well-known/oauth-protected-resource/mcp",
        ScopesSupported = ["ssh", "ssh.read"],
    };

    [Fact]
    public void A_request_that_carried_no_credential_is_not_told_its_token_is_invalid()
    {
        // RFC 6750 §3.1. There is nothing to report about a token that was never sent, and a client
        // reading `invalid_token` concludes the credential it holds is bad - which for a client
        // holding none is advice to discard something it does not have.
        var header = Configured.Header(credentialWasSent: false);

        Assert.StartsWith("Bearer ", header, StringComparison.Ordinal);
        Assert.DoesNotContain("error=", header, StringComparison.Ordinal);
    }

    [Fact]
    public void A_request_that_carried_a_credential_is_told_the_token_was_the_problem()
    {
        // The control for the assertion above: without it, that one passes against an
        // implementation that never emits an error at all.
        var header = Configured.Header(credentialWasSent: true);

        Assert.Contains("error=\"invalid_token\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public void Both_refusals_point_at_the_metadata_document()
    {
        // RFC 9728 §5.1, and the reason it is on both: a client that sent nothing needs to find the
        // document to learn where to authenticate, and a client whose token was refused needs it to
        // learn what this resource wanted. Omitting it from either leaves that client with a 401
        // and nowhere to go.
        Assert.Contains(
            "resource_metadata=\"https://sshwarden.example/.well-known/oauth-protected-resource/mcp\"",
            Configured.Header(credentialWasSent: false),
            StringComparison.Ordinal);

        Assert.Contains(
            "resource_metadata=\"https://sshwarden.example/.well-known/oauth-protected-resource/mcp\"",
            Configured.Header(credentialWasSent: true),
            StringComparison.Ordinal);
    }

    [Fact]
    public void The_scope_parameter_names_every_configured_scope()
    {
        // **The six-and-a-half-hour assertion.** A connector on the same authorization server filled
        // this from an endpoint's own requirement, so every client asked for only the scope named
        // there and the one it did not name was never granted to anybody. Space-delimited, in
        // configured order, whole. docs/DESIGN.md §6.5.0.
        Assert.Contains(
            "scope=\"ssh ssh.read\"",
            Configured.Header(credentialWasSent: false),
            StringComparison.Ordinal);
    }

    [Fact]
    public void A_mode_with_nothing_to_add_sends_the_scheme_and_nothing_else()
    {
        // Static-token mode. There is no metadata document to point at and no scope vocabulary to
        // name, and publishing an empty `scope=""` would tell a client this resource has no scopes -
        // which is a different claim from "the deployment did not say".
        Assert.Equal("Bearer", BearerChallengeParameters.None.Header(credentialWasSent: false));
        Assert.Equal(
            "Bearer error=\"invalid_token\"",
            BearerChallengeParameters.None.Header(credentialWasSent: true));
    }

    [Theory]
    // The identifier this repository's own example configures: a host and a path.
    [InlineData(
        "https://sshwarden.example/mcp",
        "/.well-known/oauth-protected-resource/mcp",
        "https://sshwarden.example/.well-known/oauth-protected-resource/mcp")]

    // §3.1: an identifier that is a bare host plus one slash loses that slash, because the suffix
    // takes the place of the slash that follows the authority.
    [InlineData(
        "https://sshwarden.example/",
        "/.well-known/oauth-protected-resource",
        "https://sshwarden.example/.well-known/oauth-protected-resource")]

    // No trailing slash at all, which is the same document at the same URL.
    [InlineData(
        "https://sshwarden.example",
        "/.well-known/oauth-protected-resource",
        "https://sshwarden.example/.well-known/oauth-protected-resource")]

    // A port survives, because it is part of the authority and dropping it would point the client
    // at a different server. A URL type that elided a default port would produce exactly this bug.
    [InlineData(
        "https://sshwarden.example:8443/mcp",
        "/.well-known/oauth-protected-resource/mcp",
        "https://sshwarden.example:8443/.well-known/oauth-protected-resource/mcp")]

    // Two path segments, so the insertion is not quietly taking only the first.
    [InlineData(
        "https://sshwarden.example/tenant/mcp",
        "/.well-known/oauth-protected-resource/tenant/mcp",
        "https://sshwarden.example/.well-known/oauth-protected-resource/tenant/mcp")]
    public void The_suffix_goes_between_the_authority_and_the_path(
        string resource, string path, string url)
    {
        // **Insertion, not appending**, which the research distillation calls the single most-failed
        // requirement in RFC 9728. Appending would publish at `…/mcp/.well-known/…`, where a
        // conformant client never looks - it constructs the inserted form first.
        Assert.Equal(path, ResourceMetadataUrl.PathFor(resource), StringComparer.Ordinal);
        Assert.Equal(url, ResourceMetadataUrl.UrlFor(resource), StringComparer.Ordinal);
    }

    [Fact]
    public void A_mixed_case_host_reaches_the_url_unchanged()
    {
        // §6 forbids Unicode normalization between the configured identifier and the one a client
        // compares against, and §3.3 has the client discard a document whose `resource` differs by a
        // byte. Every System.Uri member that would make this convenient lowercases the host, so this
        // is the assertion that goes red the day somebody reaches for one.
        const string resource = "https://SshWarden.Example/MCP";

        Assert.Equal(
            "https://SshWarden.Example/.well-known/oauth-protected-resource/MCP",
            ResourceMetadataUrl.UrlFor(resource),
            StringComparer.Ordinal);
    }
}
