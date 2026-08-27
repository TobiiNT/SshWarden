using SshWarden.Auth;

namespace SshWarden.Mcp;

/// <summary>
/// The authenticated caller for the request being handled.
/// </summary>
/// <remarks>
/// <para>
/// Registered scoped, so the authentication middleware and everything downstream of it - including
/// the per-tool gate that arrives at step 2 of docs/DESIGN.md §7 - resolve the same instance for one
/// request. That matters: the gate runs inside an MCP request filter, which is handed the request's
/// own service provider rather than an HTTP context, so a scoped service is the seam both halves can
/// reach without either of them knowing how the other was invoked.
/// </para>
/// <para>
/// Not an <c>AsyncLocal</c>. An ambient value that survives an <c>await</c> onto a pooled thread is
/// the shape where one request's identity can be read by another under load, and identity is the one
/// thing in this process where that failure is not recoverable.
/// </para>
/// </remarks>
public sealed class CallerContext
{
    /// <summary>
    /// The caller, once authentication has run; <see langword="null" /> before it has.
    /// </summary>
    public CallerIdentity? Identity { get; private set; }

    /// <summary>The caller, for code that only runs on an authenticated path.</summary>
    /// <exception cref="InvalidOperationException">
    /// Authentication has not run for this request.
    /// </exception>
    /// <remarks>
    /// Throws rather than returning an anonymous caller, and the distinction is the point: reaching
    /// here with nothing set means the authentication middleware is not in the pipeline in front of
    /// this route. That is a wiring mistake, not a caller who failed to authenticate - one is fixed
    /// by a line in startup and the other by the caller, and answering both with "anonymous" turns
    /// the first into an unauthenticated route nobody notices.
    /// </remarks>
    public CallerIdentity Require()
        => Identity ?? throw new InvalidOperationException(
            "No caller has been established for this request. SshWarden's authentication middleware "
                + "did not run in front of this route - which means the route is reachable without "
                + "a credential. Add it with UseSshWardenAuthentication before mapping the "
                + "endpoint.");

    /// <summary>Records the authenticated caller. Called once, by the middleware.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="identity" /> is null.</exception>
    /// <exception cref="InvalidOperationException">A caller is already set for this request.</exception>
    internal void Set(CallerIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        // Once per request. A second write would mean two authenticators ran, and the question of
        // which one the audit record should believe has no good answer - so it is refused here
        // rather than resolved by whichever happened to be last.
        if (Identity is not null)
        {
            throw new InvalidOperationException(
                "A caller is already established for this request. Two authentication passes ran "
                    + "over one request, which leaves the audit record's subject decided by "
                    + "ordering.");
        }

        Identity = identity;
    }
}
