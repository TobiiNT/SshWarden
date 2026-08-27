using System.Text.RegularExpressions;

namespace SshWarden.Output;

/// <summary>Masks values that look like credentials, before anything leaves this process.</summary>
/// <remarks>
/// <para>
/// The failure this exists for: an agent runs <c>cat .env</c>, the key lands in its context, and
/// from there in whatever transcript its provider keeps. Nothing downstream can take that back, so
/// the masking happens here - before the tool result is returned and before the audit record is
/// written.
/// </para>
/// <para>
/// <strong>It is best-effort and must be described that way.</strong> It matches patterns somebody
/// thought of; a credential shaped like nothing in this list goes through untouched, and no amount
/// of additions changes that. The barrier that actually holds is the one in the grant table: an SSH
/// account that cannot read the file has no secret to leak. This is the second line, and calling it
/// the first would be the false confidence this project keeps refusing to manufacture.
/// </para>
/// <para>
/// A match is replaced whole. Never a prefix, never a length hint, never the first few characters -
/// a partial credential in a log is a whole credential to somebody who can guess the rest.
/// </para>
/// <para>
/// <strong>One limit worth naming rather than discovering.</strong> The narrow patterns are anchored
/// on word boundaries, so a key with letters or digits run straight onto it - inside a longer base64
/// blob, say - is not matched. That is deliberate: dropping the anchors would mask fragments of
/// ordinary base64 output and make the redactor the thing that ruins the answer, which is how a
/// redactor gets switched off. It is also a real gap, and it is the reason the sentence above about
/// this being the second line of defence is not a formality.
/// </para>
/// </remarks>
public static partial class SecretRedactor
{
    private const int MatchTimeoutMilliseconds = 1000;

    /// <summary>
    /// The patterns, in the order they are applied.
    /// </summary>
    /// <remarks>
    /// Order is not arbitrary. The whole-block and whole-assignment rules run first, so a token
    /// inside one is masked along with everything else on that line rather than leaving the
    /// surrounding text - the variable's name, the rest of the connection string - as a hint. The
    /// narrow shapes then catch what is left standing on its own.
    /// </remarks>
    private static readonly (string Name, Func<Regex> Pattern, string Replacement)[] Rules =
    [
        // A private key is many lines and its interior is base64 that matches nothing else here, so
        // it is taken as one block or not at all.
        ("private-key-block", PrivateKeyBlock, "[redacted: private-key-block]"),

        // The name is kept and the value is masked, so a reader can still see *which* setting was
        // there. The name is matched on a secret-shaped word rather than on every assignment,
        // because masking every KEY=value would destroy ordinary output - `echo PATH=/usr/bin` is
        // not a secret, and a redactor that eats normal output gets turned off.
        ("secret-assignment", SecretAssignment, "$1=[redacted: secret-assignment]"),

        // Only the password inside a URL, so the host and the user stay readable - those are what
        // somebody debugging a connection actually needs.
        ("url-credentials", UrlCredentials, "$1:[redacted: url-credentials]@"),

        ("aws-access-key-id", AwsAccessKeyId, "[redacted: aws-access-key-id]"),
        ("github-token", GitHubToken, "[redacted: github-token]"),
        ("api-key", ApiKey, "[redacted: api-key]"),
        ("slack-token", SlackToken, "[redacted: slack-token]"),
        ("json-web-token", JsonWebToken, "[redacted: json-web-token]"),
        ("bearer-credential", BearerCredential, "[redacted: bearer-credential]"),
    ];

    /// <summary>Masks every credential-shaped value in <paramref name="text" />.</summary>
    /// <param name="text">The text to mask.</param>
    /// <exception cref="ArgumentNullException"><paramref name="text" /> is null.</exception>
    public static RedactionResult Redact(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (text.Length == 0)
        {
            return new RedactionResult { Text = text, Count = 0 };
        }

        var result = text;
        var count = 0;

        foreach (var (_, pattern, replacement) in Rules)
        {
            var regex = pattern();

            try
            {
                count += regex.Count(result);
                result = regex.Replace(result, replacement);
            }
            catch (RegexMatchTimeoutException)
            {
                // A pattern that ran out of time has matched nothing, so this text is going out
                // unmasked by that rule. Returning it silently would be the worst outcome; the
                // caller is told, and decides.
                return new RedactionResult
                {
                    Text = result,
                    Count = count,
                    TimedOut = true,
                };
            }
        }

        return new RedactionResult { Text = result, Count = count };
    }

    [GeneratedRegex(
        @"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
        RegexOptions.None,
        MatchTimeoutMilliseconds)]
    private static partial Regex PrivateKeyBlock();

    [GeneratedRegex(
        @"(?m)^([ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_]*)[ \t]*=[ \t]*\S.*$",
        RegexOptions.IgnoreCase,
        MatchTimeoutMilliseconds)]
    private static partial Regex SecretAssignment();

    [GeneratedRegex(
        @"([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/?#@]+):[^\s/?#@]+@",
        RegexOptions.None,
        MatchTimeoutMilliseconds)]
    private static partial Regex UrlCredentials();

    [GeneratedRegex(@"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex AwsAccessKeyId();

    [GeneratedRegex(@"\bgh[pousr]_[A-Za-z0-9]{20,}\b", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex GitHubToken();

    // `sk-` covers the shape several vendors settled on, and the trailing set includes `_` and `-`
    // because the longer project-scoped forms use them.
    [GeneratedRegex(@"\bsk-[A-Za-z0-9_\-]{20,}", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex ApiKey();

    [GeneratedRegex(@"\bxox[baprse]-[A-Za-z0-9\-]{10,}", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex SlackToken();

    [GeneratedRegex(
        @"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}",
        RegexOptions.None,
        MatchTimeoutMilliseconds)]
    private static partial Regex JsonWebToken();

    [GeneratedRegex(
        @"\bBearer[ \t]+[A-Za-z0-9._~+/=\-]{20,}",
        RegexOptions.IgnoreCase,
        MatchTimeoutMilliseconds)]
    private static partial Regex BearerCredential();
}

/// <summary>What redaction did to one piece of text.</summary>
public sealed class RedactionResult
{
    /// <summary>The text with credential-shaped values masked.</summary>
    public required string Text { get; init; }

    /// <summary>How many values were masked.</summary>
    /// <remarks>
    /// Reported rather than kept quiet. An agent that can see something was removed knows its view
    /// is incomplete; one that cannot draws conclusions from text it believes is whole.
    /// </remarks>
    public required int Count { get; init; }

    /// <summary>
    /// Whether a pattern ran out of time, leaving this text only partly masked.
    /// </summary>
    /// <remarks>
    /// The third value. "Nothing matched" and "the check did not finish" produce the same
    /// unmasked text and mean opposite things, and collapsing them would report an unfinished
    /// check as a clean one.
    /// </remarks>
    public bool TimedOut { get; init; }
}
