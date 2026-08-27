using System.Buffers.Text;
using System.Security.Cryptography;

namespace SshWarden.Configuration;

/// <summary>
/// A host key fingerprint in the form OpenSSH prints: <c>SHA256:</c> and unpadded base64.
/// </summary>
/// <remarks>
/// This form and no other, deliberately. The MD5 hex form OpenSSH also prints is not something to
/// pin a decision on, and accepting both would mean a deployment could downgrade its own
/// verification by pasting the wrong line out of the same command's output.
/// </remarks>
public static class HostFingerprint
{
    private const string Prefix = "SHA256:";
    private const int DigestLength = 32;

    /// <summary>Whether <paramref name="value" /> is a fingerprint this can compare against.</summary>
    /// <param name="value">The configured fingerprint.</param>
    /// <param name="problem">Why not, when this returns <see langword="false" />.</param>
    /// <exception cref="ArgumentNullException"><paramref name="value" /> is null.</exception>
    public static bool IsValid(string value, out string problem)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (!value.StartsWith(Prefix, StringComparison.Ordinal))
        {
            problem = "is not in the 'SHA256:<base64>' form OpenSSH prints. Read it with "
                + "'ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -'";
            return false;
        }

        problem = TryDecode(value, out _)
            ? string.Empty
            : "does not decode to a 32-byte SHA-256 digest";

        return problem.Length == 0;
    }

    /// <summary>
    /// Whether <paramref name="expected" /> is the fingerprint of <paramref name="hostKey" />.
    /// </summary>
    /// <param name="expected">The configured fingerprint.</param>
    /// <param name="hostKey">The host key bytes the server presented.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public static bool Matches(string expected, byte[] hostKey)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(hostKey);

        if (!TryDecode(expected, out var expectedDigest))
        {
            // An unparseable fingerprint matches nothing. The config loader refuses one at startup,
            // so reaching here means something bypassed it - and the safe answer to "I cannot tell"
            // is no.
            return false;
        }

        // Fixed-time, even though a host key fingerprint is public. It costs nothing, and the habit
        // is worth more than the reasoning about which comparisons are safe to do carelessly.
        return CryptographicOperations.FixedTimeEquals(
            expectedDigest,
            SHA256.HashData(hostKey));
    }

    private static bool TryDecode(string value, out byte[] digest)
    {
        digest = [];

        var encoded = value[Prefix.Length..];
        if (encoded.Length == 0)
        {
            return false;
        }

        // OpenSSH prints this unpadded. Base64 requires the padding, so it is restored rather than
        // the input being trimmed - which would silently accept a truncated digest.
        var padded = encoded.PadRight((encoded.Length + 3) / 4 * 4, '=');

        Span<byte> buffer = stackalloc byte[DigestLength + 4];
        if (!Convert.TryFromBase64String(padded, buffer, out var written) || written != DigestLength)
        {
            return false;
        }

        digest = buffer[..written].ToArray();
        return true;
    }
}
