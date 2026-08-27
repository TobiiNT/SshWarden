using System.Globalization;

using SshWarden.Configuration;

namespace SshWarden.Server;

/// <summary>Writes a configuration file for a deployment that has none.</summary>
/// <remarks>
/// <para>
/// The install was eight steps and most of them were the same eight everywhere: make a directory
/// with the right mode, copy a six-hundred-line example, generate a credential long enough, point
/// two state paths somewhere writable, write a rule. This does those. What it does not do is the two
/// that are genuinely the operator's - generating the key this process reaches hosts with, and
/// establishing what each host's key is.
/// </para>
/// <para>
/// <strong>It loads its own output before reporting success.</strong> A generator that drifts from
/// the loader produces a file that fails at startup on somebody else's machine, and the person who
/// ran <c>init</c> has already gone. The check costs one read and turns that into a failure here.
/// </para>
/// </remarks>
internal static class InitCommand
{
    /// <summary>The verb that selects this rather than the server.</summary>
    public const string Verb = "init";

    /// <summary>Where state goes when nothing says otherwise.</summary>
    public const string DefaultStateDirectory = "/var/log/sshwarden";

    /// <summary>Writes the file, or explains why it did not.</summary>
    /// <param name="args">Everything after the verb.</param>
    /// <exception cref="ArgumentNullException"><paramref name="args" /> is null.</exception>
    public static async Task<int> RunAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (!TryParse(args, out var options, out var parseProblems))
        {
            await WriteProblemsAsync(parseProblems).ConfigureAwait(false);
            return Program.ConfigurationExitCode;
        }

        var request = options.ToRequest();
        var problems = ConfigurationScaffold.Problems(request);
        if (problems.Count > 0)
        {
            await WriteProblemsAsync(problems).ConfigureAwait(false);
            return Program.ConfigurationExitCode;
        }

        // Refused rather than overwritten, and not offered as a flag. The file it would replace
        // holds a credential that is in somebody's client configuration, and a token silently
        // rotated by a command that looked idempotent signs them out with no message anywhere.
        if (File.Exists(options.ConfigPath))
        {
            await WriteProblemsAsync([
                $"'{options.ConfigPath}' already exists. This command will not overwrite it: the "
                    + "token in it is in somebody's client configuration, and replacing it signs "
                    + "them out. Move it aside first if that is what you want."
            ]).ConfigureAwait(false);

            return Program.ConfigurationExitCode;
        }

        var token = ConfigurationScaffold.NewToken();

        try
        {
            Create(Path.GetDirectoryName(Path.GetFullPath(options.ConfigPath)));
            Create(request.StateDirectory);

            // Written at 0600 from the start rather than written and then chmod'ed: between those
            // two calls the credential is on disk readable by everyone, and that window is exactly
            // what the loader's mode check exists to prevent.
            await WritePrivateAsync(options.ConfigPath, ConfigurationScaffold.Render(request, token))
                .ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
        {
            await WriteProblemsAsync([$"Could not write '{options.ConfigPath}': {failure.Message}"])
                .ConfigureAwait(false);

            return Program.ConfigurationExitCode;
        }

        IReadOnlyList<string> warnings;
        try
        {
            warnings = ConfigurationLoader.Load(options.ConfigPath).Warnings;
        }
        catch (SshWardenConfigurationException problem)
        {
            await Console.Error.WriteLineAsync(
                $"'{options.ConfigPath}' was written, and this build cannot load it. That is a "
                    + "defect in 'sshwarden init' rather than in what you supplied:")
                .ConfigureAwait(false);

            await Console.Error.WriteLineAsync(problem.Message).ConfigureAwait(false);
            return Program.ConfigurationExitCode;
        }

        await Console.Out.WriteLineAsync(
            string.Create(CultureInfo.InvariantCulture, $"Wrote {options.ConfigPath} (mode 0600)."))
            .ConfigureAwait(false);

        await Console.Out.WriteLineAsync(string.Empty).ConfigureAwait(false);

        // What the loader would say on the next start, said now. A file this command reports as
        // written and then a warning the operator meets on the first boot is the same information
        // delivered at the worse moment, and some of these - a listen address that is not loopback,
        // a grant reaching nothing - are worth reading before the process is a service.
        foreach (var warning in warnings)
        {
            await Console.Out.WriteLineAsync("  Warning: " + warning).ConfigureAwait(false);
        }

        if (warnings.Count > 0)
        {
            await Console.Out.WriteLineAsync(string.Empty).ConfigureAwait(false);
        }

        if (request.AuthMode == AuthModes.OAuth)
        {
            // The generated token is not printed here, because in this mode the file does not carry
            // one - the credential is minted by the authorization server. Printing it anyway was
            // the first version of this, and it handed the operator forty characters that
            // authenticate nothing and look exactly like the thing that does.
            await Console.Out.WriteLineAsync(
                $"  Callers authenticate against {request.Issuer}. Nothing in this file is a "
                    + "credential.")
                .ConfigureAwait(false);

            await Console.Out.WriteLineAsync(string.Empty).ConfigureAwait(false);
            await Console.Out.WriteLineAsync(
                $"  The [[grant]] rule is keyed on subject '{request.Subject}', which has to match "
                    + "the 'sub' its access tokens carry - not a display name.")
                .ConfigureAwait(false);
        }
        else
        {
            // To stdout, once, and nowhere else. Not into the log, which is shipped somewhere; not
            // into the file's own comments, which is where it already is.
            await Console.Out.WriteLineAsync("  Bearer token, shown once:").ConfigureAwait(false);
            await Console.Out.WriteLineAsync($"    {token}").ConfigureAwait(false);
            await Console.Out.WriteLineAsync(string.Empty).ConfigureAwait(false);
            await Console.Out.WriteLineAsync("  It is also in the file.").ConfigureAwait(false);
        }

        await Console.Out.WriteLineAsync(string.Empty).ConfigureAwait(false);
        await Console.Out.WriteLineAsync(
            "  Every rule in there grants more than a first deployment needs - narrow it before "
                + "this reaches anything real.")
            .ConfigureAwait(false);

        return 0;
    }

    private static void Create(string? directory)
    {
        if (string.IsNullOrEmpty(directory))
        {
            return;
        }

        Directory.CreateDirectory(directory);

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static async Task WritePrivateAsync(string path, string content)
    {
        if (OperatingSystem.IsWindows())
        {
            await File.WriteAllTextAsync(path, content).ConfigureAwait(false);
            return;
        }

        var stream = new FileStream(
            path,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });

        await using (stream.ConfigureAwait(false))
        {
            var writer = new StreamWriter(stream);
            await using (writer.ConfigureAwait(false))
            {
                await writer.WriteAsync(content).ConfigureAwait(false);
            }
        }
    }

    private static async Task WriteProblemsAsync(IReadOnlyList<string> problems)
    {
        await Console.Error.WriteLineAsync(
            string.Create(CultureInfo.InvariantCulture, $"sshwarden init: {problems.Count} problem(s)."))
            .ConfigureAwait(false);

        foreach (var problem in problems)
        {
            await Console.Error.WriteLineAsync($"  - {problem}").ConfigureAwait(false);
        }

        await Console.Error.WriteLineAsync(Usage).ConfigureAwait(false);
    }

    /// <summary>What the command accepts.</summary>
    /// <remarks>
    /// No <c>--token</c> and no <c>--fingerprint-from-scan</c>, and both absences are the design.
    /// A credential passed as an argument is readable by every process on the machine through
    /// <c>ps</c>, so it is generated here instead. A fingerprint read off the network is one
    /// verified by whoever answered, which is trust-on-first-use wearing a different name.
    /// </remarks>
    public const string Usage = """

        usage: sshwarden init [options]

          --config <path>              where to write it (default /etc/sshwarden/sshwarden.toml)
          --identity-file <path>       the private key this process reaches hosts with; must exist
          --host <name>=<fingerprint>  a host and the SHA256: fingerprint you verified out of band;
                                       repeatable
          --ssh-user <name>            the unix account commands run as; required with a host
          --subject <name>             who the token belongs to (default operator)
          --token-name <name>          what refusals and log lines call it (default laptop)
          --listen <addr:port>         (default 127.0.0.1:8760)
          --state-dir <path>           audit log and job registry (default /var/log/sshwarden)
          --tools <a,b,c>              which tools the generated rule covers. Defaults to every one
                                       gated on nothing but a host - read_file and tail_log also
                                       need a selector, so naming them needs --paths or --units
          --paths <a,b>                absolute path globs the rule may read under
          --units <a,b>                service units the rule may read the journal of
          --auth <mode>                static-token (default) or oauth
          --issuer <url>               the authorization server, with --auth oauth
          --resource <url>             what this server answers to in a token's audience
          --scopes <a,b>               what a client is told to ask for. Published
                                       unauthenticated, so never a host, a path or a tenant

        The token is generated, never accepted as an argument: an argument is readable by every
        process on this machine through 'ps'. Read a fingerprint over a channel you trust:

          ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -
        """;

    private sealed class Options
    {
        public string ConfigPath { get; set; } = Program.DefaultConfigPath;

        public string IdentityFile { get; set; } = "/etc/sshwarden/id_ed25519";

        public string StateDirectory { get; set; } = DefaultStateDirectory;

        public string AuthMode { get; set; } = AuthModes.StaticToken;

        public string Subject { get; set; } = "operator";

        public string TokenName { get; set; } = "laptop";

        public string Listen { get; set; } = "127.0.0.1:8760";

        public string? SshUser { get; set; }

        public List<ScaffoldHost> Hosts { get; } = [];

        public List<string>? Tools { get; set; }

        public List<string> Paths { get; } = [];

        public List<string> Units { get; } = [];

        public string? Issuer { get; set; }

        public string? Resource { get; set; }

        public List<string> Scopes { get; } = [];

        public ScaffoldRequest ToRequest() => new()
        {
            AuthMode = AuthMode,
            Subject = Subject,
            TokenName = TokenName,
            Listen = Listen,
            IdentityFile = IdentityFile,
            StateDirectory = StateDirectory,
            Hosts = Hosts,
            SshUser = SshUser,
            Tools = Tools ?? new ScaffoldRequest { IdentityFile = IdentityFile, StateDirectory = StateDirectory }.Tools,
            Paths = Paths,
            Units = Units,
            Issuer = Issuer,
            Resource = Resource,
            ScopesSupported = Scopes,
        };
    }

    private static bool TryParse(string[] args, out Options options, out IReadOnlyList<string> problems)
    {
        options = new Options();
        var found = new List<string>();

        for (var index = 0; index < args.Length; index++)
        {
            var name = args[index];

            if (!name.StartsWith("--", StringComparison.Ordinal))
            {
                found.Add($"'{name}' is not an option. Every argument here begins with '--'.");
                continue;
            }

            if (index + 1 >= args.Length)
            {
                found.Add($"{name} needs a value.");
                break;
            }

            var value = args[++index];

            switch (name)
            {
                case "--config": options.ConfigPath = value; break;
                case "--identity-file": options.IdentityFile = value; break;
                case "--state-dir": options.StateDirectory = value; break;
                case "--auth": options.AuthMode = value; break;
                case "--subject": options.Subject = value; break;
                case "--token-name": options.TokenName = value; break;
                case "--listen": options.Listen = value; break;
                case "--ssh-user": options.SshUser = value; break;

                case "--tools":
                    options.Tools = [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
                    break;

                case "--paths":
                    options.Paths.AddRange(value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                    break;

                case "--issuer": options.Issuer = value; break;
                case "--resource": options.Resource = value; break;

                case "--scopes":
                    options.Scopes.AddRange(value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                    break;

                case "--units":
                    options.Units.AddRange(value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                    break;

                case "--host":
                    // Split on the first '=' only: a fingerprint is base64 and can contain one.
                    var split = value.IndexOf('=', StringComparison.Ordinal);
                    if (split <= 0)
                    {
                        found.Add($"--host '{value}' is not 'name=SHA256:...'.");
                        break;
                    }

                    options.Hosts.Add(new ScaffoldHost(value[..split], value[(split + 1)..]));
                    break;

                // Named rather than ignored. An option this build does not know is one the operator
                // believes is taking effect, and silently dropping it writes a file that is not the
                // one they asked for.
                default:
                    found.Add($"{name} is not an option this build knows.");
                    break;
            }
        }

        problems = found;
        return found.Count == 0;
    }
}
