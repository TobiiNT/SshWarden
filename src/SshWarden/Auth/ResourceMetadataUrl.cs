namespace SshWarden.Auth;

/// <summary>
/// Where RFC 9728 says a resource's metadata document lives, built the way a client builds it.
/// </summary>
/// <remarks>
/// <para>
/// In core rather than beside the document, because the assembly that maps the routes and the code
/// that names the URL in a challenge are not always the same one, and an adapter a deployment writes
/// itself is not on the reference path of either. Two copies of this arithmetic would agree until
/// one of them learned something, and what they would disagree about is the single most-failed
/// requirement in the specification.
/// </para>
/// <para>
/// <strong>String surgery throughout, never <see cref="Uri" />.</strong> §6 forbids Unicode
/// normalization anywhere between the identifier the deployment configured and the one a client
/// compares against, and every member of <see cref="Uri" /> that would make this convenient
/// normalizes something: a lowercased host, an elided default port, a percent-decoded path. A value
/// that has been through one is a different string, and §3.3 requires the client to discard the
/// document.
/// </para>
/// </remarks>
public static class ResourceMetadataUrl
{
    /// <summary>The IANA-registered well-known suffix. RFC 9728 §8.3.</summary>
    public const string Suffix = "/.well-known/oauth-protected-resource";

    /// <summary>The path §3.1 puts the document at.</summary>
    /// <param name="resource">The resource identifier, exactly as configured.</param>
    /// <returns>The path, beginning with <see cref="Suffix" />.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="resource" /> is null.</exception>
    /// <remarks>
    /// <strong>Insertion, not appending.</strong> The suffix goes <em>between</em> the host and the
    /// path, so <c>https://mcp.example.com/mcp</c> publishes at
    /// <c>https://mcp.example.com/.well-known/oauth-protected-resource/mcp</c> - not at
    /// <c>https://mcp.example.com/mcp/.well-known/…</c>. The research distillation calls this the
    /// single most-failed requirement, and a conformant client constructs this form first, which is
    /// why a deployment serving only the root form still fails against real clients.
    /// </remarks>
    public static string PathFor(string resource)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var pathStart = PathStart(resource);
        var path = pathStart < 0 ? string.Empty : resource[pathStart..];

        // §3.1: an identifier that is a bare host plus one slash loses that slash, because the
        // slash "follows the host component" and the suffix takes its place.
        return Suffix + (path == "/" ? string.Empty : path);
    }

    /// <summary>The absolute URL of that document - what a <c>401</c> challenge names.</summary>
    /// <param name="resource">The resource identifier, exactly as configured.</param>
    /// <returns>The identifier's own origin followed by <see cref="PathFor" />.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="resource" /> is null.</exception>
    /// <remarks>
    /// Absolute rather than the path, because this is what goes in <c>resource_metadata</c> and
    /// §5.1 writes it as a URL. A client that has just been refused has no reason to assume the
    /// document is on the origin that refused it - and a resource behind a gateway on a different
    /// host is exactly the deployment where assuming it would be wrong.
    /// </remarks>
    public static string UrlFor(string resource)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var pathStart = PathStart(resource);
        var origin = pathStart < 0 ? resource : resource[..pathStart];

        return origin + PathFor(resource);
    }

    /// <summary>Where the identifier's path begins, or -1 when it has none.</summary>
    /// <remarks>
    /// Shared by both members above so they cannot disagree about where the authority ends. The
    /// scheme is skipped rather than assumed absent: without that, the slashes in <c>https://</c>
    /// are the first ones found and every identifier looks like it has a path of <c>//host</c>.
    /// </remarks>
    private static int PathStart(string resource)
    {
        var afterScheme = resource.IndexOf("://", StringComparison.Ordinal);
        var authorityStart = afterScheme < 0 ? 0 : afterScheme + 3;

        return resource.IndexOf('/', authorityStart);
    }
}
