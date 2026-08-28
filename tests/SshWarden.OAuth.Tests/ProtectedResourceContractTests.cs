using System.Net;
using System.Text.Json;

using Xunit;

namespace SshWarden.OAuth.Tests;

/// <summary>
/// RFC 9728 conformance, run against the wired pipeline rather than against a unit.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is the suite that found the missing pointer.</strong> Before it ran, this server
/// published a correct metadata document at both well-known forms and refused every request with a
/// bare <c>Bearer</c> - so a client meeting it for the first time was told it needed a credential
/// and never told where to get one. Every unit test passed the whole time, because no unit was
/// wrong: the document is right, the refusal is right, and the thing missing was the link between
/// them. Only something that drives the pipeline end to end can see that.
/// </para>
/// <para>
/// <strong>Every URL here is computed from the resource identifier by this file, not by the code
/// under test.</strong> <c>SshWarden.Auth.ResourceMetadataUrl</c> does the same §3.1 insertion in
/// production, and asking it where to look would make a defect in it compute the same wrong URL
/// twice and pass.
/// </para>
/// </remarks>
public sealed class ProtectedResourceContractTests : IAsyncLifetime
{
    /// <summary>RFC 9728 §3.1's well-known path, before any resource path is inserted.</summary>
    private const string WellKnownSuffix = "/.well-known/oauth-protected-resource";

    private OAuthPipeline _pipeline = null!;

    /// <inheritdoc />
    public async Task InitializeAsync() => _pipeline = await OAuthPipeline.StartAsync();

    /// <inheritdoc />
    public async Task DisposeAsync() => await _pipeline.DisposeAsync();

    /// <summary>
    /// RFC 9728 §3.1: the document is what a client reads to learn how to authenticate, so demanding
    /// a credential for it is a loop with no way in.
    /// </summary>
    [Fact]
    public async Task Both_well_known_forms_answer_without_a_credential()
    {
        foreach (var url in MetadataUrls())
        {
            using var response = await _pipeline.Client.GetAsync(new Uri(url, UriKind.Relative));

            Assert.True(
                response.StatusCode == HttpStatusCode.OK,
                $"{url} answered {(int)response.StatusCode}. RFC 9728 metadata has to answer without "
                    + "a credential - it is what a client reads to find out how to get one.");
        }
    }

    [Fact]
    public async Task The_metadata_document_is_json()
    {
        using var response = await _pipeline.Client.GetAsync(PathInsertedUrl());

        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    /// <summary>
    /// RFC 9728 §3.3 compares the identifier as a string. A document that normalizes it - a trailing
    /// slash added, a port dropped, a case folded - names a resource the client did not ask about.
    /// </summary>
    [Fact]
    public async Task The_documents_resource_is_the_configured_identifier_byte_for_byte()
    {
        var document = await Document();

        Assert.Equal(OAuthPipeline.Resource, document.GetProperty("resource").GetString(), StringComparer.Ordinal);
    }

    [Fact]
    public async Task The_document_names_an_authorization_server()
    {
        var document = await Document();

        Assert.True(
            document.TryGetProperty("authorization_servers", out var servers)
                && servers.ValueKind == JsonValueKind.Array
                && servers.GetArrayLength() > 0,
            "The document names no authorization server, so a client that reads it still does not "
                + "know where to authenticate.");
    }

    /// <summary>
    /// §3.1 allows both forms, and a client may reach either. Two documents that drift is a client
    /// configured from one and refused by the other.
    /// </summary>
    [Fact]
    public async Task The_two_forms_serve_the_same_document()
    {
        var insertedUrl = PathInsertedUrl();

        // A resource identifier with no path makes the two forms one URL, and there is nothing here
        // to compare. Returned rather than asserted vacuously true, so a reader of this suite is not
        // told something was checked when it was not.
        if (string.Equals(insertedUrl.OriginalString, WellKnownSuffix, StringComparison.Ordinal))
        {
            return;
        }

        var inserted = await _pipeline.Client.GetStringAsync(insertedUrl);
        var root = await _pipeline.Client.GetStringAsync(new Uri(WellKnownSuffix, UriKind.Relative));

        Assert.Equal(inserted, root, StringComparer.Ordinal);
    }

    [Fact]
    public async Task A_protected_path_with_no_credential_challenges()
    {
        using var response = await _pipeline.Client.GetAsync(new Uri(OAuthPipeline.McpPath, UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(
            response.Headers.WwwAuthenticate,
            header => string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// RFC 9728 §5.1, and the assertion this whole suite earned its place on. A challenge without
    /// <c>resource_metadata</c> tells a client it needs a credential and not where to get one.
    /// </summary>
    [Fact]
    public async Task The_metadata_url_named_in_the_challenge_is_reachable()
    {
        using var refused = await _pipeline.Client.GetAsync(new Uri(OAuthPipeline.McpPath, UriKind.Relative));

        var named = refused.Headers.WwwAuthenticate
            .Select(header => header.Parameter)
            .Where(parameter => parameter is not null)
            .Select(parameter => Parameter(parameter!, "resource_metadata"))
            .FirstOrDefault(value => value is not null);

        Assert.True(
            named is not null,
            "The challenge carries no resource_metadata parameter, so a client meeting this server "
                + "for the first time has nothing to follow.");

        // Followed as a relative path, so the test client's own base address decides the origin.
        // That is the journey a real client makes, and it does not pass by silently reaching a
        // different host.
        var path = named!.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? new Uri(named).PathAndQuery
            : named;

        using var followed = await _pipeline.Client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.True(
            followed.StatusCode == HttpStatusCode.OK,
            $"The challenge points at {named}, which answered {(int)followed.StatusCode}. That is the "
                + "URL a client is told to read to find out how to authenticate.");
    }

    /// <summary>
    /// The control for the challenge assertions above: a request that carries something is refused
    /// on the credential, not waved through and not answered with a different status.
    /// </summary>
    [Fact]
    public async Task A_credential_that_is_not_a_token_is_refused_as_unauthorized()
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(OAuthPipeline.McpPath, UriKind.Relative));

        request.Headers.TryAddWithoutValidation("Authorization", "Bearer not-a-token");

        using var response = await _pipeline.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>Both forms §3.1 allows, with the second omitted when it is the first.</summary>
    private static IEnumerable<string> MetadataUrls()
    {
        var inserted = PathInsertedUrl().OriginalString;

        yield return WellKnownSuffix;

        if (!string.Equals(inserted, WellKnownSuffix, StringComparison.Ordinal))
        {
            yield return inserted;
        }
    }

    /// <summary>
    /// RFC 9728 §3.1's path insertion, done here by string surgery rather than by
    /// <see cref="Uri" />, because §6 forbids normalizing the identifier and a parsing round trip
    /// is where normalization happens.
    /// </summary>
    private static Uri PathInsertedUrl()
    {
        var identifier = OAuthPipeline.Resource;

        var afterScheme = identifier.IndexOf("://", StringComparison.Ordinal);
        Assert.True(afterScheme > 0, $"'{identifier}' is not an absolute identifier.");

        var authorityStart = afterScheme + 3;
        var pathStart = identifier.IndexOf('/', authorityStart);
        var path = pathStart < 0 ? string.Empty : identifier[pathStart..];

        // A bare host plus a single slash loses that slash: §3.1 puts the suffix where the slash
        // that follows the authority was.
        if (path == "/")
        {
            path = string.Empty;
        }

        return new Uri(WellKnownSuffix + path, UriKind.Relative);
    }

    private async Task<JsonElement> Document()
    {
        var body = await _pipeline.Client.GetStringAsync(PathInsertedUrl());

        using var parsed = JsonDocument.Parse(body);

        return parsed.RootElement.Clone();
    }

    /// <summary>
    /// RFC 6750 §3 makes challenge parameters quoted strings, so the value is read between the
    /// quotes rather than to the next comma - a URL contains commas legally.
    /// </summary>
    private static string? Parameter(string parameters, string name)
    {
        var marker = name + "=\"";
        var start = parameters.IndexOf(marker, StringComparison.Ordinal);

        if (start < 0)
        {
            return null;
        }

        start += marker.Length;

        var end = parameters.IndexOf('"', start);

        return end < 0 ? null : parameters[start..end];
    }
}
