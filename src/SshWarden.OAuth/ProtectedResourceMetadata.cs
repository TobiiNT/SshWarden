using System.Text.Json.Serialization;

using SshWarden.Auth;
using SshWarden.Configuration;

namespace SshWarden.OAuth;

/// <summary>
/// The RFC 9728 protected-resource metadata document.
/// </summary>
/// <remarks>
/// <para>
/// Written here rather than taken from a library, because it belongs to the resource server and
/// nothing else in this assembly's dependency does it. It is what a client reads to find out where
/// to authenticate, which is what lets an MCP client discover the flow with nothing configured by
/// hand.
/// </para>
/// <para>
/// Only the four members this server can answer for. RFC 9728 §2 defines more, and a document
/// carrying an empty or invented value for one of them is worse than one that leaves it out - the
/// client believes what is there.
/// </para>
/// </remarks>
public sealed class ProtectedResourceMetadata
{
    /// <summary>The resource identifier, exactly as configured.</summary>
    /// <remarks>
    /// <strong>Byte for byte, and never rebuilt from a URL type.</strong> §3.3 has the client
    /// compare this against the identifier it inserted the well-known suffix into, and §6 forbids
    /// Unicode normalization anywhere in between - so a value that has been through
    /// <c>System.Uri</c> is a different string, and the client is required to discard the document.
    /// The failure surfaces on the client as a generic connection problem while this server's log
    /// shows a clean 200.
    /// </remarks>
    [JsonPropertyName("resource")]
    public required string Resource { get; init; }

    /// <summary>Where to authenticate.</summary>
    [JsonPropertyName("authorization_servers")]
    public required IReadOnlyList<string> AuthorizationServers { get; init; }

    /// <summary>What a client is told to ask for.</summary>
    /// <remarks>
    /// Omitted entirely when nothing is configured rather than published as an empty array: an
    /// empty list reads as "this resource has no scopes", and "the deployment did not say" is a
    /// different thing.
    /// </remarks>
    [JsonPropertyName("scopes_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    /// <summary>How a token may be presented. The header, and only the header.</summary>
    /// <remarks>
    /// RFC 6750 also defines a form field and a query parameter. Neither is offered: a token in a
    /// query string lands in every access log between the client and here.
    /// </remarks>
    [JsonPropertyName("bearer_methods_supported")]
    public IReadOnlyList<string> BearerMethodsSupported { get; } = ["header"];

    /// <summary>Builds the document from the loaded configuration.</summary>
    /// <param name="options">The <c>[auth.oauth]</c> table.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options" /> is null.</exception>
    public static ProtectedResourceMetadata For(OAuthSection options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return new ProtectedResourceMetadata
        {
            Resource = options.Resource,
            AuthorizationServers = [options.Issuer],
            ScopesSupported = options.ScopesSupported.Count > 0 ? options.ScopesSupported : null,
        };
    }

    // Where this document lives - the well-known suffix, the path-inserted form and the absolute
    // URL - is SshWarden.Auth.ResourceMetadataUrl, in core. It moved there because the code that
    // names the same URL in a challenge is not always on this assembly's reference path. Nothing
    // about the arithmetic changed; it has one home instead of the two it was about to have.
}
