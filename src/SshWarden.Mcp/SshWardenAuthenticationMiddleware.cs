using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using SshWarden.Auth;
using SshWarden.Mcp.Diagnostics;

namespace SshWarden.Mcp;

/// <summary>
/// Authenticates every request to the MCP endpoint, or answers 401 with a bearer challenge.
/// </summary>
/// <remarks>
/// <para>
/// Middleware rather than an MCP request filter, and the difference is measured rather than
/// stylistic. By the time an MCP tool filter runs, the Streamable HTTP transport has already sent
/// the <c>200</c> status line - measured 2026-08-25 and written up in docs/DESIGN.md §6.5.8 - so nothing
/// at that layer can produce a <c>401</c>. Authentication has to happen before the transport
/// handler is entered, and this is the last place that is true.
/// </para>
/// <para>
/// That is also the line between this and the per-tool gate of step 2: <em>this</em> answers "is
/// there a caller at all", with an HTTP status and a challenge a client knows how to act on. The
/// gate answers "may this caller run this tool with these arguments", and can only say so in the
/// text of a tool result. They are different questions with different reach, and merging them would
/// mean picking one of the two answers to give up.
/// </para>
/// </remarks>
public sealed class SshWardenAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SshWardenAuthenticationMiddleware> _logger;
    private readonly BearerChallengeParameters _challenge;

    /// <summary>Builds the middleware.</summary>
    /// <param name="next">The rest of the pipeline.</param>
    /// <param name="logger">Where refusals are recorded.</param>
    /// <param name="challenge">
    /// What this deployment's challenge carries beyond the scheme. <c>AddSshWarden</c> registers
    /// <see cref="BearerChallengeParameters.None" /> with <c>TryAdd</c>, so a mode with a metadata
    /// document to point at registers its own before that call and wins.
    /// </param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public SshWardenAuthenticationMiddleware(
        RequestDelegate next,
        ILogger<SshWardenAuthenticationMiddleware> logger,
        BearerChallengeParameters challenge)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(challenge);

        _next = next;
        _logger = logger;
        _challenge = challenge;
    }

    /// <summary>Authenticates the request, then continues or refuses.</summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public async Task InvokeAsync(
        HttpContext context,
        ISshWardenAuthenticator authenticator,
        CallerContext caller)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authenticator);
        ArgumentNullException.ThrowIfNull(caller);

        // Routing has already run, so the endpoint - and whether whoever mapped it said it may be
        // reached without a credential - is known here. Nothing is exempt by path.
        if (context.GetEndpoint()?.Metadata.GetMetadata<AllowUnauthenticated>() is not null)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var request = new AuthenticationRequest
        {
            AuthorizationHeader = context.Request.Headers.Authorization.ToString() is { Length: > 0 } header
                ? header
                : null,
            Principal = context.User,
        };

        var result = await authenticator
            .AuthenticateAsync(request, context.RequestAborted)
            .ConfigureAwait(false);

        if (!result.IsAuthenticated)
        {
            // The detail goes to the operator's log and nowhere else. What the caller learns is the
            // difference between "you sent no credential" and "what you sent is not accepted",
            // which is what RFC 6750 gives a client to act on - and nothing about which credential,
            // which subject, or how close a guess was.
            //
            // Two levels, because the two mean different things on a public endpoint. A request with
            // no credential at all is what every scanner on the internet sends and is not news; a
            // request carrying a credential that was not accepted is somebody who has one, or thinks
            // they do, and is the line worth an alert. Logging both at the same level makes the
            // second invisible inside the first.
            var path = context.Request.Path.Value;

            if (result.Refusal == AuthenticationRefusal.NoCredential)
            {
                McpLog.NoCredential(_logger, path, result.Refusal, result.Detail);
            }
            else
            {
                McpLog.RejectedCredential(_logger, path, result.Refusal!, result.Detail);
            }

            Challenge(context, result.Refusal!);
            return;
        }

        caller.Set(result.Identity!);
        await _next(context).ConfigureAwait(false);
    }

    private void Challenge(HttpContext context, string refusal)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;

        // RFC 6750 §3.1: a request that carried no credential gets no `error`, because there is
        // nothing to report about a token that was never sent - the client's next step is to acquire
        // one, not to conclude the one it holds is bad. Everything else is invalid_token.
        //
        // Everything past the scheme comes from the mode that was wired, and in OAuth mode that is
        // the `resource_metadata` pointer plus the whole advertised scope list. **The whole list,
        // never a subset**: a connector built on the same authorization server filled that parameter
        // from an endpoint-level scope requirement, which told every client to ask for only the
        // scope named there; the scope it did not name was never granted to anybody, and every
        // operation needing it failed for six and a half hours before the cause was found.
        // docs/DESIGN.md §6.5.0 has the full account. The cheap version: this header is what clients
        // read to decide what to ask for, so anything that narrows it silently narrows every token
        // the deployment will ever see. BearerChallengeParameters holds that rule where the value is
        // built.
        context.Response.Headers.WWWAuthenticate =
            _challenge.Header(refusal != AuthenticationRefusal.NoCredential);

        // No body. There is nothing to say to an unauthenticated caller that the status and the
        // challenge do not already say, and a body here is a place for detail to leak into later.
    }
}
