using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

using SshWarden.Configuration;

namespace SshWarden.Auth;

/// <summary>
/// Authenticates against the credentials listed in the config file.
/// </summary>
/// <remarks>
/// <para>
/// The default, and the reason someone can run SshWarden without also running an authorization
/// server (docs/DESIGN.md §6.2). It is weaker than the OAuth authenticator in exactly one way that
/// matters - a static token does not expire, so the only revocation is editing the file and
/// restarting - and that is stated in the README rather than left for a reader to notice.
/// </para>
/// <para>
/// <strong>Two of the five identity values are derived here.</strong> A static token has no grant
/// and no token identifier, because nothing issued it. Rather than leaving those null and putting a
/// hole in every audit record, this mints one of each per configured token at startup:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       The grant id groups a run of commands into one working session. A static token never
///       refreshes, so the honest analogue of a grant is "this token, for the life of this
///       process" - which is what a per-entry, per-start value is. Restarting the server starts a
///       new session in the log, which is true.
///     </description>
///   </item>
///   <item>
///     <description>
///       The token id identifies the credential. There is exactly one token in a static token's
///       family, forever, so it is minted alongside and kept distinct - the two answer different
///       questions even when a deployment has no refreshes to tell them apart.
///     </description>
///   </item>
/// </list>
/// <para>
/// Both carry a prefix naming what they are, so a line in the audit log says on its own that these
/// were derived here rather than issued by an authorization server. That is the point of §4.2's
/// test: read one record, look at nothing else, understand what happened.
/// </para>
/// </remarks>
public sealed class StaticTokenAuthenticator : ISshWardenAuthenticator
{
    /// <summary>The value recorded as <see cref="CallerIdentity.Source" />.</summary>
    public const string SourceName = "static-token";

    private const string GrantIdPrefix = "sw_gid_";
    private const string TokenIdPrefix = "sw_jti_";

    private readonly IReadOnlyList<Entry> _entries;

    /// <summary>Builds an authenticator over the configured tokens.</summary>
    /// <param name="tokens">
    /// The <c>[[auth.static_token]]</c> entries, already validated by the config loader.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="tokens" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="tokens" /> is empty.</exception>
    public StaticTokenAuthenticator(IReadOnlyList<StaticTokenEntry> tokens)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        // Not merely unhelpful - an authenticator that can authenticate nobody is indistinguishable
        // at every later call site from one that is working and being given wrong credentials. The
        // config loader refuses this case first; this is the backstop for a caller constructing one
        // directly.
        if (tokens.Count == 0)
        {
            throw new ArgumentException(
                "No static tokens were configured, so this authenticator could never authenticate "
                    + "anyone. SshWarden refuses to start without a way to authenticate a caller; "
                    + "there is no mode that skips it.",
                nameof(tokens));
        }

        _entries = [.. tokens.Select(Entry.From)];
    }

    /// <inheritdoc />
    public string Name => SourceName;

    /// <inheritdoc />
    public ValueTask<AuthenticationResult> AuthenticateAsync(
        AuthenticationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (!BearerCredential.TryParse(request.AuthorizationHeader, out var credential, out var refusal))
        {
            return ValueTask.FromResult(AuthenticationResult.Refuse(
                refusal,
                refusal == AuthenticationRefusal.NoCredential
                    ? "No Authorization header was sent."
                    : "The Authorization header is not a well-formed 'Bearer <credential>' value."));
        }

        var presented = Sha256(credential);

        // Every entry is compared, and the loop does not stop at the first match. Stopping early
        // would make the work done depend on which entry matched, which is the same class of
        // observable the fixed-time comparison below exists to remove - and keeping it uniform
        // costs one boolean.
        Entry? matched = null;
        foreach (var entry in _entries)
        {
            // The credentials are hashed to a fixed 32 bytes before comparison. FixedTimeEquals
            // requires equal lengths and returns false immediately otherwise, so comparing the raw
            // strings would leak the configured credential's length through the fast path. Hashing
            // first makes every comparison the same size and the same cost, whatever was presented.
            if (CryptographicOperations.FixedTimeEquals(presented, entry.TokenHash))
            {
                matched = entry;
            }
        }

        if (matched is null)
        {
            return ValueTask.FromResult(AuthenticationResult.Refuse(
                AuthenticationRefusal.UnknownCredential,

                // Names no entry, quotes no part of what was presented, and does not say whether
                // anything came close. An operator can still act on this: it means the credential
                // reached the server and is not one of the configured ones.
                "The bearer credential presented matches no configured static token."));
        }

        return ValueTask.FromResult(AuthenticationResult.Success(new CallerIdentity
        {
            Subject = matched.Subject,
            ClientId = matched.ClientId,
            GrantId = matched.GrantId,
            TokenId = matched.TokenId,

            // A static token carries no scope claim, so the scope question is not answered here at
            // all - authority comes from the grant table. This is the state that must stay distinct
            // from "a claim that could not be read", which grants nothing.
            ScopeClaim = ScopeClaimState.Absent,
            Scopes = new HashSet<string>(StringComparer.Ordinal),
            Source = SourceName,
        }));
    }

    private static byte[] Sha256(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

    private static string NewId(string prefix)
    {
        // 128 bits from the cryptographic generator. Not a counter and not a timestamp: the same
        // rule the job identifiers of docs/DESIGN.md §6.5.3 are held to, for the same reason - an
        // identifier that appears in a log and can be guessed is an identifier somebody can claim.
        var bytes = RandomNumberGenerator.GetBytes(16);
        return prefix + Base64Url.EncodeToString(bytes);
    }

    private sealed class Entry
    {
        private Entry(StaticTokenEntry source)
        {
            Subject = source.Subject;

            // Verbatim. Not trimmed, not lowercased - see CallerIdentity.ClientId.
            ClientId = source.ClientId ?? source.Name;
            TokenHash = Sha256(source.Token);
            GrantId = NewId(GrantIdPrefix);
            TokenId = NewId(TokenIdPrefix);
        }

        public string Subject { get; }

        public string ClientId { get; }

        public byte[] TokenHash { get; }

        public string GrantId { get; }

        public string TokenId { get; }

        public static Entry From(StaticTokenEntry source) => new(source);
    }
}
