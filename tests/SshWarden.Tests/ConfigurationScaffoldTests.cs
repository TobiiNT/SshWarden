using SshWarden.Configuration;

using Xunit;

namespace SshWarden.Tests;

/// <summary>What `sshwarden init` writes, and what it refuses to write.</summary>
/// <remarks>
/// The load test is the one that matters. A generator that drifts from the loader produces a file
/// that fails at startup on somebody else's machine, long after whoever ran the command has gone.
/// </remarks>
public sealed class ConfigurationScaffoldTests
{
    private const string Fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    [Fact]
    public void What_it_writes_is_what_this_build_loads()
    {
        using var scratch = new ScratchDirectory();

        var request = Request(scratch);
        Assert.Empty(ConfigurationScaffold.Problems(request));

        using var file = TempConfigFile.Write(ConfigurationScaffold.Render(request, ConfigurationScaffold.NewToken()));

        // Reaching the next line is the assertion: the loader reports every problem in one throw.
        var loaded = ConfigurationLoader.Load(file.Path);

        // And nothing it merely tolerated. A generated file that draws a warning is this command
        // telling an operator to start from a configuration we would not.
        Assert.Empty(loaded.Warnings);

        Assert.Equal("dev-web-1", Assert.Single(loaded.Configuration.Hosts).Name);
        Assert.Equal("deploy", Assert.Single(loaded.Configuration.Grants).SshUser);
        // Not all seven: read_file and tail_log are gated on a selector too, and a rule naming them
        // with neither is one the loader refuses. This test is how that was found.
        Assert.DoesNotContain(ToolNames.ReadFile, loaded.Configuration.Grants[0].Tools);
        Assert.Contains(ToolNames.Run, loaded.Configuration.Grants[0].Tools);
        Assert.Contains(ToolNames.StartJob, loaded.Configuration.Grants[0].Tools);
    }

    [Fact]
    public void A_file_with_no_hosts_loads_and_says_what_it_cannot_do()
    {
        // A real state: somebody setting the server up before they have decided what it reaches.
        // It has to start, and every tool call is refused by a grant table with no rules in it.
        using var scratch = new ScratchDirectory();

        var request = new ScaffoldRequest
        {
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
        };

        Assert.Empty(ConfigurationScaffold.Problems(request));

        using var file = TempConfigFile.Write(ConfigurationScaffold.Render(request, ConfigurationScaffold.NewToken()));
        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.Contains(loaded.Warnings, w => w.Contains("No [[host]]", StringComparison.Ordinal));
        Assert.Contains(loaded.Warnings, w => w.Contains("No [[grant]]", StringComparison.Ordinal));
    }

    [Fact]
    public void The_generated_token_is_long_enough_that_the_loader_takes_it()
    {
        // The floor is 32 characters because a static token does not expire, so being unguessable
        // is the whole of its security. Generated at 32 bytes, which is 43 characters unpadded -
        // the floor is a floor, not the target.
        var token = ConfigurationScaffold.NewToken();

        Assert.True(token.Length >= 32, $"'{token}' is {token.Length} characters");

        // And url-safe, because it goes in an Authorization header and into client configuration
        // files that a person copies by hand.
        Assert.DoesNotContain('+', token);
        Assert.DoesNotContain('/', token);
        Assert.DoesNotContain('=', token);
    }

    [Fact]
    public void Two_runs_do_not_produce_the_same_token()
    {
        // Cheap, and it is the check that a generator wired to a constant seed would fail.
        var tokens = new HashSet<string>(Enumerable.Range(0, 32).Select(_ => ConfigurationScaffold.NewToken()));

        Assert.Equal(32, tokens.Count);
    }

    [Fact]
    public void An_oauth_config_it_writes_is_one_this_build_loads()
    {
        // The second shape, and the reason `--auth` is a flag with more than one answer at all. It
        // writes no token: in this mode the credential is minted by an authorization server, and a
        // static one left in the file would be a second way in that nothing revokes.
        using var scratch = new ScratchDirectory();

        var request = new ScaffoldRequest
        {
            AuthMode = AuthModes.OAuth,
            Issuer = "https://auth.example.com",
            Resource = "https://sshwarden.example.com/mcp",
            ScopesSupported = ["ssh:read", "ssh:exec"],
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
            Hosts = [new ScaffoldHost("dev-web-1", Fingerprint)],
            SshUser = "deploy",
        };

        Assert.Empty(ConfigurationScaffold.Problems(request));

        using var file = TempConfigFile.Write(ConfigurationScaffold.Render(request, ConfigurationScaffold.NewToken()));
        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.Empty(loaded.Warnings);
        Assert.Equal(AuthModes.OAuth, loaded.Configuration.Auth.Mode);
        Assert.Equal("https://auth.example.com", loaded.Configuration.Auth.OAuth!.Issuer);
        Assert.Empty(loaded.Configuration.Auth.StaticTokens);
    }

    [Theory]
    [InlineData("--issuer")]
    [InlineData("--resource")]
    public void OAuth_without_both_halves_is_refused(string flag)
    {
        using var scratch = new ScratchDirectory();

        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            AuthMode = AuthModes.OAuth,
            Issuer = flag == "--issuer" ? null : "https://auth.example.com",
            Resource = flag == "--resource" ? null : "https://sshwarden.example.com/mcp",
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
        });

        Assert.Contains(problems, p => p.Contains(flag, StringComparison.Ordinal));
    }

    [Fact]
    public void A_scope_naming_a_host_is_refused_before_it_can_be_published()
    {
        using var scratch = new ScratchDirectory();

        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            AuthMode = AuthModes.OAuth,
            Issuer = "https://auth.example.com",
            Resource = "https://sshwarden.example.com/mcp",
            ScopesSupported = ["ssh:exec:prod-web-1.example.com"],
            Hosts = [new ScaffoldHost("prod-web-1.example.com", Fingerprint)],
            SshUser = "deploy",
            Subject = "someone",
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
        });

        Assert.Contains(problems, p => p.Contains("published", StringComparison.Ordinal));
    }

    [Fact]
    public void The_oauth_file_does_not_claim_to_hold_a_credential()
    {
        // It does not: the token is minted by the authorization server and never written here. A
        // header saying otherwise sends somebody looking for a secret that is not in the file, which
        // is the same mistake as printing a generated token in a mode that authenticates with none.
        using var scratch = new ScratchDirectory();

        var text = ConfigurationScaffold.Render(
            new ScaffoldRequest
            {
                AuthMode = AuthModes.OAuth,
                Issuer = "https://auth.example.com",
                Resource = "https://sshwarden.example.com/mcp",
                Subject = "someone",
                IdentityFile = scratch.Key,
                StateDirectory = scratch.Path,
            },
            ConfigurationScaffold.NewToken());

        Assert.DoesNotContain("holds a credential", text, StringComparison.Ordinal);

        // And still says the mode matters, because it does for a different reason: this file decides
        // which hosts are reachable and as which unix account.
        Assert.Contains("0600", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("stories.read")]
    [InlineData("ssh.exec")]
    [InlineData("ssh:dbadmin")]
    public void A_scope_that_names_no_host_of_this_deployment_is_accepted(string scope)
    {
        // The control, and the rule it pins: this and the loader have to refuse the same set. The
        // first version of both refused any scope carrying a dot, which is not a hostname test -
        // these three name nothing. `db` is a declared host here on purpose, because it occurs
        // inside `ssh:dbadmin` and a substring rule would refuse it.
        using var scratch = new ScratchDirectory();

        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            AuthMode = AuthModes.OAuth,
            Issuer = "https://auth.example.com",
            Resource = "https://sshwarden.example.com/mcp",
            ScopesSupported = [scope],
            Hosts = [new ScaffoldHost("db", Fingerprint)],
            SshUser = "deploy",
            Subject = "someone",
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
        });

        Assert.Empty(problems);
    }

    [Fact]
    public void A_key_that_is_not_there_is_refused_with_the_command_that_makes_one()
    {
        using var scratch = new ScratchDirectory();

        var request = new ScaffoldRequest
        {
            IdentityFile = "/nowhere/id_ed25519",
            StateDirectory = scratch.Path,
        };

        var problems = ConfigurationScaffold.Problems(request);

        Assert.Contains(problems, p => p.Contains("does not exist", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("ssh-keygen", StringComparison.Ordinal));
    }

    [Fact]
    public void A_fingerprint_that_is_not_one_is_refused_with_the_command_that_reads_it()
    {
        // The one thing this command will not do for you. A fingerprint read off the network is one
        // verified by whoever answered, which is trust-on-first-use wearing a different name - and
        // the host-key design refuses it with no way to switch it off.
        using var scratch = new ScratchDirectory();

        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
            Hosts = [new ScaffoldHost("dev-web-1", "not-a-fingerprint")],
            SshUser = "deploy",
        });

        Assert.Contains(problems, p => p.Contains("ssh-keyscan", StringComparison.Ordinal));
    }

    [Fact]
    public void A_read_tool_with_no_selector_is_refused_before_the_file_is_written()
    {
        // The loader refuses this too, and being refused there means `init` reported success for a
        // configuration that does not start. Caught here instead, with the flag names.
        using var scratch = new ScratchDirectory();

        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
            Hosts = [new ScaffoldHost("dev-web-1", Fingerprint)],
            SshUser = "deploy",
            Tools = [ToolNames.Run, ToolNames.ReadFile],
        });

        Assert.Contains(problems, p => p.Contains("--paths", StringComparison.Ordinal));
    }

    [Fact]
    public void A_read_tool_with_a_selector_loads()
    {
        // The control. Without it the test above passes against a scaffold that refuses every read
        // tool, which would make the flag useless in exactly the way it is meant to avoid.
        using var scratch = new ScratchDirectory();

        var request = new ScaffoldRequest
        {
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
            Hosts = [new ScaffoldHost("dev-web-1", Fingerprint)],
            SshUser = "deploy",
            Tools = [ToolNames.Run, ToolNames.ReadFile, ToolNames.TailLog],
            Paths = ["/var/log/**"],
            Units = ["nginx"],
        };

        Assert.Empty(ConfigurationScaffold.Problems(request));

        using var file = TempConfigFile.Write(ConfigurationScaffold.Render(request, ConfigurationScaffold.NewToken()));
        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.Empty(loaded.Warnings);
        Assert.Equal("/var/log/**", Assert.Single(loaded.Configuration.Grants[0].Paths).ToString());
    }

    [Fact]
    public void A_host_with_no_account_to_run_as_is_refused()
    {
        using var scratch = new ScratchDirectory();

        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
            Hosts = [new ScaffoldHost("dev-web-1", Fingerprint)],
        });

        Assert.Contains(problems, p => p.Contains("--ssh-user", StringComparison.Ordinal));
    }

    [Fact]
    public void An_auth_mode_this_build_cannot_load_is_refused_by_name()
    {
        // The same rule the loader enforces, one step earlier: a config that parses and then
        // authenticates nothing says the deployment is authenticating one way while it is not
        // authenticating at all. The refusal enumerates what this build does support.
        //
        // This used to name `oauth` as the unsupported one, which stopped being true the moment
        // there was an authenticator behind it - a mode name is added here in the same change that
        // makes it work, so a test picking one at random goes stale by design.
        using var scratch = new ScratchDirectory();

        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            AuthMode = "mtls",
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
        });

        Assert.Contains(problems, p => p.Contains(AuthModes.StaticToken, StringComparison.Ordinal));
    }

    [Fact]
    public void A_tool_this_build_does_not_have_is_refused()
    {
        using var scratch = new ScratchDirectory();

        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
            Hosts = [new ScaffoldHost("dev-web-1", Fingerprint)],
            SshUser = "deploy",
            Tools = ["run", "rm_minus_rf"],
        });

        Assert.Contains(problems, p => p.Contains("rm_minus_rf", StringComparison.Ordinal));
    }

    [Fact]
    public void Every_problem_is_reported_at_once()
    {
        // An operator who fixes one problem per run learns about the next one on the next run.
        var problems = ConfigurationScaffold.Problems(new ScaffoldRequest
        {
            AuthMode = "mtls",
            IdentityFile = "/nowhere/id_ed25519",
            StateDirectory = "/tmp",
            Hosts = [new ScaffoldHost("dev-web-1", "nope")],
        });

        Assert.True(problems.Count >= 4, string.Join(" | ", problems));
    }

    [Fact]
    public void A_name_carrying_a_quote_does_not_break_the_file_it_is_written_into()
    {
        // Nothing should ever get here - but a generator whose output does not parse produces a
        // failure at startup on a machine nobody is watching, so the escaping is checked rather
        // than assumed.
        using var scratch = new ScratchDirectory();

        var request = new ScaffoldRequest
        {
            IdentityFile = scratch.Key,
            StateDirectory = scratch.Path,
            Subject = "some\"one\\else",
        };

        using var file = TempConfigFile.Write(ConfigurationScaffold.Render(request, ConfigurationScaffold.NewToken()));

        Assert.Equal("some\"one\\else", ConfigurationLoader.Load(file.Path).Configuration.Auth.StaticTokens[0].Subject);
    }

    private static ScaffoldRequest Request(ScratchDirectory scratch) => new()
    {
        IdentityFile = scratch.Key,
        StateDirectory = scratch.Path,
        Hosts = [new ScaffoldHost("dev-web-1", Fingerprint)],
        SshUser = "deploy",
    };

    /// <summary>A directory holding a key file at the mode the scaffold requires.</summary>
    private sealed class ScratchDirectory : IDisposable
    {
        public ScratchDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), "sshwarden-scaffold", Guid.NewGuid().ToString("n"));

            Directory.CreateDirectory(Path);

            Key = System.IO.Path.Combine(Path, "id_ed25519");
            File.WriteAllText(Key, string.Empty);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(Key, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }

        public string Path { get; }

        public string Key { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
