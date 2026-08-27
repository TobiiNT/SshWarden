using System.Security.Cryptography;
using System.Text.Json;

namespace SshWarden.Testing;

/// <summary>
/// One RSA key and the JWKS document publishing its public half.
/// </summary>
/// <remarks>
/// <para>
/// Generated per fixture rather than checked in. A key file in a repository is a credential in a
/// test fixture whatever it opens, and this repository's rule about that has no exception for "it
/// opens nothing" - the next person to copy the fixture is the one who finds out what it opened.
/// </para>
/// <para>
/// <strong>Nothing signs a token with it.</strong> Both suites that use this need the key set only
/// so the resource server starts: a server holding no keys refuses everything, which is a refusal
/// with the wrong cause behind it. Every assertion downstream is about a refusal or about the
/// metadata document, and neither needs a token that validates.
/// </para>
/// <para>
/// Linked into both OAuth suites rather than copied, because the two would agree about the shape of
/// a JWKS right up until one of them learned something.
/// </para>
/// </remarks>
internal sealed class TestSigningKey : IDisposable
{
    private readonly RSA _key = RSA.Create(2048);

    /// <summary>The key id this key is published under.</summary>
    public string KeyId { get; } = "test-key";

    /// <summary>The JWKS document, as an authorization server would serve it.</summary>
    /// <remarks>
    /// Written by hand rather than through a JWK library, so the bytes under test are the bytes on
    /// the wire. RFC 7517 §4 and RFC 7518 §6.3.1: <c>n</c> and <c>e</c> are base64url of the
    /// unsigned big-endian modulus and exponent, with no padding.
    /// </remarks>
    public string Jwks()
    {
        var parameters = _key.ExportParameters(includePrivateParameters: false);

        var key = new
        {
            kty = "RSA",
            use = "sig",
            alg = "RS256",
            kid = KeyId,
            n = Base64Url(parameters.Modulus!),
            e = Base64Url(parameters.Exponent!),
        };

        return JsonSerializer.Serialize(new { keys = new[] { key } });
    }

    /// <summary>The discovery document pointing at a JWKS on the same origin.</summary>
    /// <param name="issuer">The issuer, exactly as the resource server is configured with it.</param>
    /// <param name="jwksUri">Where the key set is served.</param>
    /// <remarks>
    /// <c>jwks_uri</c> is read rather than assumed to be <c>/.well-known/jwks.json</c>. A resource
    /// server that hardcodes that path cannot follow an authorization server publishing its keys
    /// anywhere else, which is most of them.
    /// </remarks>
    public static string Discovery(string issuer, string jwksUri) =>
        JsonSerializer.Serialize(new
        {
            issuer,
            jwks_uri = jwksUri,
            authorization_endpoint = issuer + "/authorize",
            token_endpoint = issuer + "/token",
            response_types_supported = ResponseTypes,
            subject_types_supported = SubjectTypes,
            id_token_signing_alg_values_supported = SigningAlgorithms,
        });

    private static readonly string[] ResponseTypes = ["code"];
    private static readonly string[] SubjectTypes = ["public"];
    private static readonly string[] SigningAlgorithms = ["RS256"];

    public void Dispose() => _key.Dispose();

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
