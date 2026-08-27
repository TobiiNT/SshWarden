using Microsoft.Extensions.Logging;

using SshWarden.Diagnostics;

namespace SshWarden.Server;

/// <summary>
/// Everything the server host says, which is only what happens before and around serving.
/// </summary>
/// <remarks>
/// Ids come from <see cref="LogEvents.Server" />. A host is the one place allowed to know how the
/// whole thing is put together, and these two lines are that: what the config file objected to
/// without refusing, and the fact that a port is open.
/// </remarks>
public static partial class ServerLog
{
    /// <summary>Something the config file says that loaded anyway.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="warning">The loader's own sentence, passed through unchanged.</param>
    /// <remarks>
    /// Unchanged on purpose. The loader writes these for an operator and rewording one here would
    /// mean two texts for one problem, of which the one in the log is the one somebody reads.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Server + 1,
        EventName = "ConfigurationWarning",
        Level = LogLevel.Warning,
        Message = "{Warning}")]
    public static partial void ConfigurationWarning(ILogger logger, string warning);

    /// <summary>The process is serving.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="listen">The listen address.</param>
    /// <param name="mcpPath">Where the MCP endpoint is mapped.</param>
    /// <param name="authMode">Which authentication mode is in force.</param>
    /// <remarks>
    /// Written from the application-started callback rather than before the run, because in OAuth
    /// mode startup can still fail after the pipeline is built - fetching the authorization server's
    /// signing keys is a hosted service. Logged unconditionally, this printed "SshWarden listening
    /// on ..." and then the process died, which is the one sentence an operator greps for to decide
    /// it is up.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Server + 2,
        EventName = "Listening",
        Level = LogLevel.Information,
        Message = "SshWarden listening on {Listen}, MCP at {McpPath}, authenticating with {AuthMode}.")]
    public static partial void Listening(ILogger logger, string listen, string mcpPath, string authMode);
}
