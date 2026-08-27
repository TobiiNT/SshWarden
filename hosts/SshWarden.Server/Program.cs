using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SshWarden.Auth;
using SshWarden.OAuth;
using SshWarden.Configuration;
using SshWarden.Mcp;

namespace SshWarden.Server;

/// <summary>The SshWarden process.</summary>
public static class Program
{
    /// <summary>
    /// The exit code used when the config file will not do.
    /// </summary>
    /// <remarks>
    /// 78 is <c>EX_CONFIG</c> from sysexits.h, which service managers and supervisors already
    /// understand as "this will not fix itself by restarting". Exiting 1 for everything makes a
    /// typo in the config indistinguishable from a crash, and the two want opposite responses.
    /// </remarks>
    public const int ConfigurationExitCode = 78;

    /// <summary>
    /// The exit code used when something this process depends on could not be reached.
    /// </summary>
    /// <remarks>
    /// 69 is <c>EX_UNAVAILABLE</c> from sysexits.h, and the distinction from
    /// <see cref="ConfigurationExitCode" /> is what a supervisor does next. A bad config fails
    /// identically on every restart, so restarting is wasted; an authorization server that is still
    /// booting is reachable on the next attempt, so restarting is the fix. Returning one code for
    /// both would make a deployment ordering problem look like a typo.
    /// </remarks>
    public const int UpstreamExitCode = 69;

    /// <summary>The environment variable naming the config file.</summary>
    public const string ConfigPathVariable = "SSHWARDEN_CONFIG";

    /// <summary>Where the config file is read from when nothing says otherwise.</summary>
    public const string DefaultConfigPath = "/etc/sshwarden/sshwarden.toml";

    /// <summary>Starts the server.</summary>
    /// <param name="args">Command-line arguments. Only <c>--config &lt;path&gt;</c> is read.</param>
    /// <returns>0 on a clean shutdown, <see cref="ConfigurationExitCode" /> on a bad config.</returns>
    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        // A verb rather than a flag, and only one of them: `sshwarden init` writes a config file and
        // exits, everything else starts the server exactly as it did before this existed.
        if (args.Length > 0 && args[0] == InitCommand.Verb)
        {
            return await InitCommand.RunAsync(args[1..]).ConfigureAwait(false);
        }

        var configPath = ResolveConfigPath(args);

        ConfigurationLoadResult loaded;
        try
        {
            loaded = ConfigurationLoader.Load(configPath);
        }
        catch (SshWardenConfigurationException problem)
        {
            // Straight to stderr, before any logging is configured: the reason the process is not
            // starting has to reach the person who ran it even when the thing that is wrong is the
            // configuration a logger would have been built from.
            await Console.Error.WriteLineAsync(problem.Message).ConfigureAwait(false);
            return ConfigurationExitCode;
        }

        var configuration = loaded.Configuration;

        var builder = WebApplication.CreateBuilder(args);

        // The listen address comes from the config file rather than from ASPNETCORE_URLS or a
        // command-line argument, so that the one file an operator secures is the one that decides
        // what this process exposes. docs/DESIGN.md §6.1 puts the credentials in the same file for the
        // same reason - an argument is readable by every process on the box through 'ps'.
        builder.WebHost.UseUrls($"http://{configuration.Server.Listen}");

        // Before AddSshWarden, which is where every seam here goes: its registrations are TryAdd, so
        // one made first wins and one made after silently does nothing. AddSshWarden then checks
        // that this ran - a config saying `oauth` with no authenticator registered is a process that
        // would otherwise serve the MCP endpoint with nothing in front of it.
        if (configuration.Auth.Mode == AuthModes.OAuth)
        {
            builder.Services.AddSshWardenOAuth(configuration);
        }

        builder.Services.AddSshWarden(configuration);

        // From here to the end of Main, because two of the things that stop a process starting are
        // only reachable after the container is built: an SSH key that is not a key, which the pool
        // reads when MapSshWarden resolves it, and an authorization server that does not answer.
        // Both used to arrive as an unhandled exception with a stack trace, which is the shape of a
        // defect rather than of something an operator can fix.
        try
        {
            return await ServeAsync(builder, loaded, configuration).ConfigureAwait(false);
        }
        catch (SshWardenConfigurationException problem)
        {
            await Console.Error.WriteLineAsync(problem.Message).ConfigureAwait(false);
            return ConfigurationExitCode;
        }
        catch (AuthorizationServerUnreachableException unreachable)
        {
            // The one line, and no stack trace: everything under it is this process's own hosting
            // plumbing, and printing it buries the sentence naming the server that did not answer.
            // A defect still gets its trace, because only these two types are caught.
            await Console.Error.WriteLineAsync("SshWarden will not start: " + unreachable.Message)
                .ConfigureAwait(false);
            return UpstreamExitCode;
        }
    }

    private static async Task<int> ServeAsync(
        WebApplicationBuilder builder,
        ConfigurationLoadResult loaded,
        SshWardenConfiguration configuration)
    {
        var app = builder.Build();

        foreach (var warning in loaded.Warnings)
        {
            ServerLog.ConfigurationWarning(app.Logger, warning);
        }

        // Explicit, because the authentication middleware reads endpoint metadata to find the
        // endpoints that opted out of it, and before routing there is no endpoint to read.
        app.UseRouting();

        // Before SshWarden's own middleware, which reads the principal this one establishes. The
        // other order hands it a request nothing has authenticated, and the seam's own contract says
        // to refuse that rather than fall back to the header - so it would present as every caller
        // being rejected.
        if (configuration.Auth.Mode == AuthModes.OAuth)
        {
            app.UseSshWardenOAuth();
        }

        app.UseSshWardenAuthentication();

        app.MapSshWardenHealth();

        if (configuration.Auth.Mode == AuthModes.OAuth)
        {
            // Unauthenticated on purpose: it is what a client reads to find out where to
            // authenticate, so a credential requirement on it is a chicken-and-egg no client can
            // break out of.
            app.MapSshWardenOAuth();
        }

        app.MapSshWarden(configuration);

        var listen = configuration.Server.Listen;
        var mcpPath = configuration.Server.McpPath;
        var authMode = configuration.Auth.Mode;

        // On the started event rather than before the run; ServerLog.Listening carries why.
        app.Lifetime.ApplicationStarted.Register(() => ServerLog.Listening(app.Logger, listen, mcpPath, authMode));

        await app.RunAsync().ConfigureAwait(false);
        return 0;
    }

    private static string ResolveConfigPath(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        for (var index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], "--config", StringComparison.Ordinal))
            {
                return args[index + 1];
            }
        }

        var fromEnvironment = Environment.GetEnvironmentVariable(ConfigPathVariable);
        return string.IsNullOrWhiteSpace(fromEnvironment) ? DefaultConfigPath : fromEnvironment;
    }
}
