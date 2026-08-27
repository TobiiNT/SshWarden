using System.Net;
using System.Net.Http.Headers;

using Xunit;

namespace SshWarden.Mcp.Tests;

public sealed class AuthenticationMiddlewareTests
{
    [Fact]
    public async Task An_unmarked_route_is_closed_without_a_credential()
    {
        // The structural test of the whole file. Authentication runs over everything and routes opt
        // out by carrying metadata at the place they are mapped, so a route added by somebody not
        // thinking about authentication is closed. Under the shape this replaces - running the
        // middleware only over the MCP path - this route would answer 200 and nothing would say so.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await pipeline.Client.GetAsync(new Uri("/probe/unmarked", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_unmarked_route_opens_for_a_valid_credential()
    {
        // The control. Without it, a middleware that refused everything would look like a working
        // deny-by-default.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await Get(pipeline, "/probe/unmarked", AuthenticatedPipeline.ValidToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task The_health_endpoint_is_reachable_without_a_credential()
    {
        // Marked, deliberately: a reverse proxy and a container runtime need to ask whether the
        // process is up before anybody has a token. It answers that and nothing about what the
        // deployment is configured to reach.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await pipeline.Client.GetAsync(new Uri("/health", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A_request_with_no_credential_is_challenged_without_an_error_code()
    {
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await pipeline.Client.GetAsync(new Uri(AuthenticatedPipeline.McpPath, UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // RFC 6750 §3.1: no error code for a request that carried no credential. The client's next
        // step is to acquire one, not to conclude the one it holds is bad.
        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Bearer", challenge.Scheme);
        Assert.Null(challenge.Parameter);
    }

    [Fact]
    public async Task A_request_with_a_rejected_credential_is_challenged_with_invalid_token()
    {
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await Get(
            pipeline,
            AuthenticatedPipeline.McpPath,
            "wrong-token-wrong-token-wrong-token-wrong");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Bearer", challenge.Scheme);
        Assert.Equal("error=\"invalid_token\"", challenge.Parameter);
    }

    [Fact]
    public async Task A_challenge_names_no_scope_at_all()
    {
        // The line that must never appear here. In the OAuth deployment of step 8 this parameter is
        // what MCP clients read to decide what to ask for - before any metadata document - so a
        // scope named here narrows every token the deployment will ever be given. A connector on
        // the same authorization server filled it from an endpoint-level scope requirement and
        // spent six and a half hours with every write operation failing, because the scope it did
        // not name was never granted to anybody. docs/DESIGN.md §6.5.0.
        //
        // A static token deployment has no scopes to name, so today this is trivially true. It is
        // pinned now so that the change which adds scopes has to come past this assertion.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await pipeline.Client.GetAsync(new Uri(AuthenticatedPipeline.McpPath, UriKind.Relative));

        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.DoesNotContain("scope", challenge.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_refusal_tells_the_caller_nothing_beyond_the_challenge()
    {
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await Get(
            pipeline,
            AuthenticatedPipeline.McpPath,
            "wrong-token-wrong-token-wrong-token-wrong");

        // The operator's log carries which rule refused and why. The caller gets a status and a
        // challenge - an empty body has nowhere for detail to leak into later.
        Assert.Empty(await response.Content.ReadAsStringAsync(CancellationToken.None));
    }

    [Fact]
    public async Task An_authenticated_caller_reaches_the_route_as_the_configured_subject()
    {
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await Get(pipeline, "/probe/caller", AuthenticatedPipeline.ValidToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            AuthenticatedPipeline.Subject,
            await response.Content.ReadAsStringAsync(CancellationToken.None));
    }

    [Fact]
    public async Task An_authenticated_request_reaches_the_mcp_endpoint()
    {
        // Not a 401, which is all this asserts. What the transport answers a bare GET with is the
        // transport's business - and by the time it answers, the status line is already sent, which
        // is exactly why authentication has to happen here rather than in an MCP filter
        // (docs/DESIGN.md §6.5.8).
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await Get(
            pipeline,
            AuthenticatedPipeline.McpPath,
            AuthenticatedPipeline.ValidToken);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<HttpResponseMessage> Get(
        AuthenticatedPipeline pipeline,
        string path,
        string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(path, UriKind.Relative));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await pipeline.Client.SendAsync(request, CancellationToken.None);
    }
}
