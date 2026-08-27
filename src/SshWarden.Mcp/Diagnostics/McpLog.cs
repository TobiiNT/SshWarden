using Microsoft.Extensions.Logging;

using SshWarden.Diagnostics;

namespace SshWarden.Mcp.Diagnostics;

/// <summary>
/// Everything <c>SshWarden.Mcp</c> can say to an operator, in one file.
/// </summary>
/// <remarks>
/// <para>
/// The request path. Ids come from <see cref="LogEvents.Mcp" />, and the reasoning for a range per
/// assembly rather than a number chosen per event is on <see cref="LogEvents" />.
/// </para>
/// <para>
/// <strong>Nothing here carries what a caller sent.</strong> A refusal is logged by its rule and its
/// subject, never by the credential, the command or the arguments - this is the copy that leaves the
/// process for whatever aggregates logs, and everything worth keeping about a call is in the audit
/// record instead.
/// </para>
/// </remarks>
public static partial class McpLog
{
    /// <summary>A request arrived with no credential at all.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="path">The request path.</param>
    /// <param name="refusal">The refusal code.</param>
    /// <param name="detail">What the operator is told, which the caller is not.</param>
    /// <remarks>
    /// Information, not Warning, and the split from <see cref="RejectedCredential" /> is the whole
    /// reason there are two of these. A request with no credential is what every scanner on the
    /// internet sends and is not news; one carrying a credential that was not accepted is somebody
    /// who has one, or thinks they do. Logged at one level, the second is invisible inside the first.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Mcp + 1,
        EventName = "NoCredential",
        Level = LogLevel.Information,
        Message = "No credential was presented for {Path}: {Refusal}. {Detail}")]
    public static partial void NoCredential(ILogger logger, string? path, string? refusal, string? detail);

    /// <summary>A request carried a credential that was not accepted.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="path">The request path.</param>
    /// <param name="refusal">The refusal code.</param>
    /// <param name="detail">What the operator is told, which the caller is not.</param>
    /// <remarks>The line worth alerting on. See <see cref="NoCredential" /> for why it is its own level.</remarks>
    [LoggerMessage(
        EventId = LogEvents.Mcp + 2,
        EventName = "RejectedCredential",
        Level = LogLevel.Warning,
        Message = "A credential presented for {Path} was not accepted: {Refusal}. {Detail}")]
    public static partial void RejectedCredential(ILogger logger, string? path, string refusal, string? detail);

    /// <summary>The grant table refused a tool call.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="tool">The tool.</param>
    /// <param name="subject">The caller.</param>
    /// <param name="refusedBy">Which rule refused it.</param>
    /// <remarks>
    /// The operator's copy of what the caller was told. Alongside the audit record rather than
    /// instead of it: the record is the evidence, and this is what shows up in whatever is already
    /// tailing the service.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Mcp + 3,
        EventName = "ToolRefused",
        Level = LogLevel.Information,
        Message = "Refused tool {Tool} for {Subject}: {RefusedBy}.")]
    public static partial void ToolRefused(ILogger logger, string tool, string subject, string refusedBy);
}
