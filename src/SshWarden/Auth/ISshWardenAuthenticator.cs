using System.Security.Claims;

namespace SshWarden.Auth;

/// <summary>
/// Turns an inbound request's credentials into a <see cref="CallerIdentity" />, or refuses.
/// </summary>
/// <remarks>
/// <para>
/// The one seam docs/DESIGN.md §6.2 requires. SshWarden ships two implementations and must work with
/// either without the rest of the code knowing which is loaded:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="StaticTokenAuthenticator" /> - zero dependencies, enough for someone running
///       this on their own VPS, and the default.
///     </description>
///   </item>
///   <item>
///     <description>
///       An OAuth authenticator over an external authorization server, added at step 8 of
///       docs/DESIGN.md §7. It is deliberately last: with a static token the SSH half can ship and be
///       used for real while the abstraction holds the place, and a bug in the SSH layer stays
///       distinguishable from a bug in token validation.
///     </description>
///   </item>
/// </list>
/// <para>
/// Which one runs is a config choice, never a compile-time flag. Requiring an OAuth server to run
/// this at all would mean a stranger has to stand up two <c>0.x</c> services from the same author
/// before they can run one command - a barrier higher than the tool is worth.
/// </para>
/// </remarks>
public interface ISshWardenAuthenticator
{
    /// <summary>
    /// A short, stable name for this implementation, recorded as <see cref="CallerIdentity.Source" />.
    /// </summary>
    /// <remarks>
    /// Ordinal English, matched character-for-character in log queries - not page text, not
    /// localized.
    /// </remarks>
    string Name { get; }

    /// <summary>Authenticate one request.</summary>
    /// <param name="request">What the request carried.</param>
    /// <param name="cancellationToken">Cancels the check.</param>
    /// <returns>An identity, or a refusal naming which rule refused.</returns>
    /// <remarks>
    /// Returns a refusal rather than throwing, because a caller presenting no credential is the
    /// ordinary case on a public endpoint and not an exceptional one. Exceptions are left for the
    /// authenticator itself being broken - an authorization server that cannot be reached, a key
    /// set that will not parse - which is a different thing and deserves a different signal.
    /// </remarks>
    ValueTask<AuthenticationResult> AuthenticateAsync(
        AuthenticationRequest request,
        CancellationToken cancellationToken);
}

/// <summary>What an inbound request carried that an authenticator may look at.</summary>
/// <remarks>
/// <para>
/// Two properties, and both are here because the two implementations read different ones. The
/// static-token authenticator reads the raw header, because it is the only thing that can validate
/// its own credential. An OAuth authenticator reads <see cref="Principal" />, because by the time
/// it runs the framework's bearer handler has already validated the signature, the expiry and the
/// audience, and re-parsing the header would mean re-deciding what was already decided - the shape
/// that lets two validators disagree.
/// </para>
/// <para>
/// Passing the whole HTTP context instead would have worked and is rejected on purpose: it would
/// put an ASP.NET Core dependency on the seam, and an authenticator that can reach the request path,
/// the remote address and the response is one that can start making decisions those things should
/// not be part of.
/// </para>
/// </remarks>
public sealed class AuthenticationRequest
{
    /// <summary>
    /// The raw <c>Authorization</c> header value, or <see langword="null" /> if none was sent.
    /// </summary>
    /// <remarks>
    /// Raw, so the authenticator decides what a well-formed credential is. Nothing upstream trims,
    /// splits or lowercases it.
    /// </remarks>
    public string? AuthorizationHeader { get; init; }

    /// <summary>
    /// The principal an upstream authentication handler established, if any.
    /// </summary>
    /// <remarks>
    /// <see langword="null" /> for a static-token deployment, where nothing upstream authenticates.
    /// An authenticator that needs this and finds it null must refuse rather than fall back to the
    /// header: reaching past a validator that did not run is how a request with an unverified token
    /// gets treated as verified.
    /// </remarks>
    public ClaimsPrincipal? Principal { get; init; }
}
