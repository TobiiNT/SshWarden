using SshWarden.Configuration;

using Xunit;

namespace SshWarden.Tests;

/// <summary>
/// What the config loader accepts and what it refuses.
/// </summary>
/// <remarks>
/// Every refusal here has a sibling proving the same path accepts what it should. A test that only
/// asserts a refusal cannot tell a working rule from a loader that refuses everything.
/// </remarks>
public sealed class ConfigurationLoaderTests
{
    private const string Token = "0123456789012345678901234567890123456789";

    private const string Minimal = """
        [auth]
        mode = "static-token"

        [[auth.static_token]]
        name = "laptop"
        subject = "someone"
        token = "0123456789012345678901234567890123456789"
        """;

    [Fact]
    public void A_minimal_file_loads()
    {
        using var file = TempConfigFile.Write(Minimal);

        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.Equal(AuthModes.StaticToken, loaded.Configuration.Auth.Mode);
        Assert.Single(loaded.Configuration.Auth.StaticTokens);

        // It loads, and it says what it cannot do. A file with authentication and nothing else is a
        // real state - a deployment part way through setup - so it starts, and every tool call is
        // refused by a grant table with no rules in it.
        Assert.Contains(loaded.Warnings, w => w.Contains("No [[host]]", StringComparison.Ordinal));
        Assert.Contains(loaded.Warnings, w => w.Contains("No [[grant]]", StringComparison.Ordinal));
    }

    [Fact]
    public void The_example_file_this_repository_ships_loads_once_its_placeholder_is_filled_in()
    {
        // The example is the file a deployment copies, and the loader refuses unknown keys - so a
        // block added to the code and spelled differently in the example is a startup failure that
        // happens on somebody else's machine rather than on this one. Nothing was checking it: the
        // README tells a reader to install it, and every table in it was until now unverified.
        //
        // Two substitutions, and they are the only things about the example this does not check.
        // The state paths are under /var/log, which the loader refuses when it cannot write there.
        // The token is a placeholder, deliberately - see the sibling below.
        using var file = TempConfigFile.Write(Runnable(File.ReadAllText(ExamplePath()), out _, out _));

        // The loader reports every problem it found in one exception, so reaching the next line at
        // all is the assertion: the example has nothing wrong with it.
        var loaded = ConfigurationLoader.Load(file.Path);

        // And nothing it merely tolerated. A complete example that still draws a warning is telling
        // its reader to start from a configuration we would not.
        Assert.Empty(loaded.Warnings);

        // And it is the whole example rather than a file that happens to parse: every table the
        // code knows about is present in it and reached its section.
        Assert.NotEmpty(loaded.Configuration.Hosts);
        Assert.NotEmpty(loaded.Configuration.Grants);
        Assert.NotEmpty(loaded.Configuration.Watch.Paths);
        Assert.NotEmpty(loaded.Configuration.Jobs.Registry);
        Assert.NotEmpty(loaded.Configuration.Jobs.RemoteDirectory);
    }

    [Fact]
    public void The_example_file_carries_no_token_that_would_work()
    {
        // The control for the test above, and the more important half. An example config carrying a
        // usable credential is a credential in everybody's deployment, so the shipped one is a
        // placeholder - and a placeholder that merely worked would be worse than a real secret,
        // because nobody would ever be told to change it.
        using var file = TempConfigFile.Write(Runnable(File.ReadAllText(ExamplePath()), out var token, out _));

        File.WriteAllText(
            file.Path,
            File.ReadAllText(file.Path).Replace(token, "replace-me", StringComparison.Ordinal));

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        // Refused, and told how to make a real one. A refusal that only says no leaves somebody
        // guessing at what length and what alphabet.
        Assert.Contains(
            problem.Problems,
            p => p.Contains("openssl rand", StringComparison.Ordinal));
    }

    /// <summary>The shipped example with the three things a deployment must supply filled in.</summary>
    private static string Runnable(string example, out string token, out string keyPath)
    {
        token = new string('a', 40);

        var directory = Path.Combine(Path.GetTempPath(), "sshwarden-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        var slashed = directory.Replace("\\", "/", StringComparison.Ordinal);
        keyPath = slashed + "/id_ed25519";

        return example
            .Replace("/var/log/sshwarden", slashed, StringComparison.Ordinal)
            .Replace("/etc/sshwarden/id_ed25519", TempConfigFile.IdentityFilePlaceholder, StringComparison.Ordinal)
            .Replace("\"replace-me\"", "\"" + token + "\"", StringComparison.Ordinal);
    }

    [Fact]
    public void A_private_key_that_is_not_there_is_refused_by_name()
    {
        // It used to be left to the SSH layer, which reports it as a DirectoryNotFoundException out
        // of the container while endpoints are being mapped - thirty lines of stack trace naming a
        // third-party library, for a key the operator simply had not generated yet.
        //
        // The control is The_example_file_this_repository_ships_loads_once_its_placeholder_is_filled_in
        // above, which supplies a key at a path that exists and loads.
        // The placeholder left unsubstituted, so the config names a path nothing created.
        var example = Runnable(File.ReadAllText(ExamplePath()), out _, out _)
            .Replace(TempConfigFile.IdentityFilePlaceholder, "/nowhere/id_ed25519", StringComparison.Ordinal);

        using var file = TempConfigFile.Write(example);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        Assert.Contains(
            problem.Problems,
            p => p.Contains("/nowhere/id_ed25519", StringComparison.Ordinal)
                && p.Contains("does not exist", StringComparison.Ordinal));

        // And told how to make one, because a refusal that only says no leaves somebody guessing.
        Assert.Contains(problem.Problems, p => p.Contains("ssh-keygen", StringComparison.Ordinal));
    }

    private static string ExamplePath()
    {
        // Walked up from the test assembly rather than pinned as a relative path, so it survives a
        // change to the output layout.
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName,
                "hosts",
                "SshWarden.Server",
                "sshwarden.example.toml");

            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        // Named rather than returned as a null the assertion would blame on the example.
        throw new FileNotFoundException(
            "sshwarden.example.toml was not found above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void OAuth_mode_with_no_oauth_table_is_refused()
    {
        // A mode that parses and loads nothing says the deployment is authenticating one way while
        // it is not authenticating at all. Without an issuer there is no authorization server to
        // trust, so nobody could ever authenticate.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "oauth"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(() => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains("[auth.oauth]", StringComparison.Ordinal));
    }

    [Fact]
    public void OAuth_mode_with_an_issuer_and_a_resource_loads()
    {
        // The control. Without it the test above passes against a loader that refuses oauth
        // outright, which would make the mode useless in exactly the way it is meant to avoid.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "https://auth.example.com"
            resource = "https://sshwarden.example.com/mcp"
            scopes_supported = ["ssh:read", "ssh:exec"]
            """);

        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.Equal(AuthModes.OAuth, loaded.Configuration.Auth.Mode);
        Assert.Equal("https://auth.example.com", loaded.Configuration.Auth.OAuth!.Issuer);
        Assert.Equal(2, loaded.Configuration.Auth.OAuth.ScopesSupported.Count);
    }

    [Theory]
    [InlineData("ssh run", "a space")]
    [InlineData("ssh\"run", "a double quote")]
    [InlineData("ssh\\run", "a backslash")]
    [InlineData("ssh\u00A0run", "U+00A0")]
    public void A_scope_that_is_not_a_scope_token_is_refused(string scope, string named)
    {
        // RFC 6749 §3.3 allows printable ASCII without the space, the quote or the backslash, and
        // this list is both published in the metadata document and spliced into the `scope`
        // parameter of every 401. A space makes one scope read as two and publishes a name no
        // authorization server will issue; a quote ends the challenge parameter early and takes the
        // resource_metadata pointer after it out of the challenge with it.
        using var file = TempConfigFile.Write($"""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "https://auth.example.com"
            resource = "https://sshwarden.example.com/mcp"
            scopes_supported = ["{scope.Replace("\\", "\\\\").Replace("\"", "\\\"")}"]
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(() => ConfigurationLoader.Load(file.Path));

        // The character is named, not just the scope. A file may hold several scopes that look
        // alike on screen, and "which one and which character" is the whole of what is actionable.
        Assert.Contains(problem.Problems, p => p.Contains(named, StringComparison.Ordinal));
    }

    [Fact]
    public void An_empty_scope_is_refused()
    {
        // Refused by the string-array reader rather than by the scope-token rule beside it, and
        // asserted here so that stays true: an empty string in this list would otherwise be
        // published to every client that reads the metadata document, and the scope-token rule
        // would never see it to say so.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "https://auth.example.com"
            resource = "https://sshwarden.example.com/mcp"
            scopes_supported = ["ssh", ""]
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(() => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p =>
            p.Contains("auth.oauth.scopes_supported", StringComparison.Ordinal)
            && p.Contains("non-empty", StringComparison.Ordinal));
    }

    [Fact]
    public void The_punctuation_a_scope_is_allowed_to_carry_loads()
    {
        // The control, and it is doing real work: every separator an authorization server in the
        // wild uses to namespace a scope is punctuation, so a rule that reached one character too
        // far would refuse the scopes most deployments actually configure. Each of these is inside
        // RFC 6749 §3.3's set.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "https://auth.example.com"
            resource = "https://sshwarden.example.com/mcp"
            scopes_supported = ["ssh:read", "ssh.write", "ssh-admin", "ssh_ops", "https://api.example.com/ssh"]
            """);

        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.Equal(5, loaded.Configuration.Auth.OAuth!.ScopesSupported.Count);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("resource")]
    public void An_issuer_or_resource_carrying_a_quote_is_refused(string key)
    {
        // Both are spliced into a WWW-Authenticate parameter, where RFC 6750 §3 wraps every value in
        // a quoted string - an embedded quote ends it early and everything after it, the
        // resource_metadata pointer included, is read as something else. Neither has any business
        // carrying one: RFC 3986 does not permit a raw quote in a URI.
        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["issuer"] = "https://auth.example.com",
            ["resource"] = "https://sshwarden.example.com/mcp",
        };

        values[key] = values[key] + "\\\"evil";

        using var file = TempConfigFile.Write($"""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "{values["issuer"]}"
            resource = "{values["resource"]}"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(() => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p =>
            p.Contains($"auth.oauth.{key}", StringComparison.Ordinal)
            && p.Contains("quote or a backslash", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("resource")]
    public void An_authorization_server_reached_over_plain_http_is_refused(string key)
    {
        // Both decide who this server trusts and what it answers to. Over plain http either can be
        // rewritten by whoever carries the packets, and the failure looks like a working deployment.
        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["issuer"] = "https://auth.example.com",
            ["resource"] = "https://sshwarden.example.com/mcp",
        };

        values[key] = "http://insecure.example.com";

        using var file = TempConfigFile.Write($"""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "{values["issuer"]}"
            resource = "{values["resource"]}"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(() => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains($"auth.oauth.{key}", StringComparison.Ordinal));
    }

    [Fact]
    public void A_scope_naming_a_declared_host_is_refused_because_the_list_is_published()
    {
        // The RFC 9728 document is unauthenticated, so a scope naming a host tells anyone who asks
        // for it that the host exists. docs/DESIGN.md §6.5.4, which is also why the grant table
        // and not a scope decides which machine a call reaches.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "https://auth.example.com"
            resource = "https://sshwarden.example.com/mcp"
            scopes_supported = ["ssh:exec:prod-web-1.example.com"]

            [ssh]
            identity_file = "{identity_file}"

            [[host]]
            name = "prod-web-1.example.com"
            fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(() => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains("published", StringComparison.Ordinal));
    }

    [Fact]
    public void A_scope_naming_a_host_by_its_address_is_refused_too()
    {
        // The name is what a grant matches on, but the address is the disclosure: a host declared
        // under a friendly name and reached at an internal one publishes the internal one if a
        // scope carries it. Checking only Name would let exactly that through.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "https://auth.example.com"
            resource = "https://sshwarden.example.com/mcp"
            scopes_supported = ["ssh:exec:db-1.internal.example.com"]

            [ssh]
            identity_file = "{identity_file}"

            [[host]]
            name = "database"
            address = "db-1.internal.example.com"
            fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(() => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains("db-1.internal.example.com", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("stories.read")]
    [InlineData("ssh.exec")]
    [InlineData("ssh:dbadmin")]
    public void An_ordinary_scope_that_names_nothing_is_accepted(string scope)
    {
        // The control, and it is the reason this rule was rewritten. The first version refused any
        // scope containing a dot, which is not a hostname test: these three name nothing. The third
        // is the substring trap, and the host below is named to spring it - `db` occurs inside
        // `ssh:dbadmin`, so a rule matching by substring refuses a scope that publishes nothing.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "https://auth.example.com"
            resource = "https://sshwarden.example.com/mcp"
            scopes_supported = ["SCOPE"]

            [ssh]
            identity_file = "{identity_file}"

            [[host]]
            name = "db"
            fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            """.Replace("SCOPE", scope, StringComparison.Ordinal));

        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.Equal([scope], loaded.Configuration.Auth.OAuth!.ScopesSupported);
    }

    [Fact]
    public void A_scope_carrying_a_path_separator_is_a_warning_rather_than_a_refusal()
    {
        // Two readings that cannot be told apart from here: a path published along with the rest of
        // the list, or a URL-shaped scope, which is how more than one authorization server names
        // them. Refusing would break the second to catch the first.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "oauth"

            [auth.oauth]
            issuer = "https://auth.example.com"
            resource = "https://sshwarden.example.com/mcp"
            scopes_supported = ["https://auth.example.com/scopes/ssh.exec"]
            """);

        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.Contains(loaded.Warnings, w => w.Contains("path separator", StringComparison.Ordinal));
    }

    [Fact]
    public void An_absent_server_table_takes_the_documented_defaults()
    {
        using var file = TempConfigFile.Write(Minimal);

        var server = ConfigurationLoader.Load(file.Path).Configuration.Server;

        // Loopback, because misconfiguring this one line publishes SSH access to production hosts.
        Assert.Equal("127.0.0.1:8760", server.Listen);
        Assert.Equal("/mcp", server.McpPath);
    }

    [Fact]
    public void A_missing_file_is_refused_by_name()
    {
        var path = Path.Combine(Path.GetTempPath(), "sshwarden-tests", Guid.NewGuid().ToString("n"));

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(path));

        Assert.Contains(path, problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_readable_beyond_its_owner_is_refused()
    {
        using var file = TempConfigFile.Write(
            Minimal,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);

        if (OperatingSystem.IsWindows())
        {
            // Not skipped on a platform without file modes - asserted differently, because the two
            // outcomes are both things this must get right. Where the check cannot run, the loader
            // has to say it did not run rather than pass quietly, or a deployment concludes the
            // file is protected because nothing complained.
            Assert.Contains(
                ConfigurationLoader.Load(file.Path).Warnings,
                w => w.Contains("unmeasured", StringComparison.Ordinal));
            return;
        }

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains("chmod 600", StringComparison.Ordinal));
    }

    [Fact]
    public void A_file_readable_only_by_its_owner_is_accepted()
    {
        // The control for the test above. Without it, a loader that refused every file would look
        // like a working permission check.
        using var file = TempConfigFile.Write(
            Minimal,
            UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var loaded = ConfigurationLoader.Load(file.Path);

        Assert.NotNull(loaded.Configuration);
    }

    [Fact]
    public void A_missing_auth_table_is_refused()
    {
        using var file = TempConfigFile.Write("""
            [server]
            listen = "127.0.0.1:8760"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains("[auth]", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unsupported_auth_mode_is_refused_and_says_what_is_supported()
    {
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "none"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        // The point of the message: an operator who wrote "none" hoping to skip authentication
        // learns that no such mode exists, rather than guessing at spelling.
        Assert.Contains(
            problem.Problems,
            p => p.Contains("static-token", StringComparison.Ordinal));
    }

    [Fact]
    public void Static_token_mode_with_no_tokens_is_refused()
    {
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "static-token"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        Assert.Contains(
            problem.Problems,
            p => p.Contains("no [[auth.static_token]] blocks", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("unknown_root_key = 1", "unknown_root_key")]
    [InlineData("[server]\nlissen = \"127.0.0.1:1\"", "server.lissen")]
    [InlineData("[auth]\nmode = \"static-token\"\nrealm = \"x\"", "auth.realm")]
    public void An_unknown_key_is_refused_by_its_full_path(string extra, string expected)
    {
        // The expensive failure this prevents: a misspelled key is a rule that silently does not
        // apply. The config says one thing, the process does another, and nothing anywhere says so.
        using var file = TempConfigFile.Write(extra + "\n\n" + Minimal);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void An_unknown_key_inside_a_token_block_is_refused()
    {
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "static-token"

            [[auth.static_token]]
            name = "laptop"
            subject = "someone"
            token = "0123456789012345678901234567890123456789"
            scopes = ["ssh:read"]
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        // Named on purpose: a static token carries no scope claim, so a 'scopes' key here would be
        // an operator believing they had narrowed a credential that is not narrowed at all.
        Assert.Contains(
            problem.Problems,
            p => p.Contains("auth.static_token[0].scopes", StringComparison.Ordinal));
    }

    [Fact]
    public void Every_problem_is_reported_at_once()
    {
        using var file = TempConfigFile.Write("""
            [server]
            listen = "not-an-address"
            mcp_path = "mcp"

            [auth]
            mode = "static-token"

            [[auth.static_token]]
            name = "laptop"
            token = "short"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        // Four independent mistakes, one restart. A loader that stopped at the first would make
        // fixing this file four restarts, and the person doing it has usually just been paged.
        Assert.Equal(4, problem.Problems.Count);
        Assert.Contains(problem.Problems, p => p.Contains("server.listen", StringComparison.Ordinal));
        Assert.Contains(problem.Problems, p => p.Contains("server.mcp_path", StringComparison.Ordinal));
        Assert.Contains(problem.Problems, p => p.Contains("subject is not set", StringComparison.Ordinal));
        Assert.Contains(problem.Problems, p => p.Contains("characters", StringComparison.Ordinal));
    }

    [Fact]
    public void A_short_token_is_refused_without_quoting_it()
    {
        const string Secret = "hunter2";

        using var file = TempConfigFile.Write($"""
            [auth]
            mode = "static-token"

            [[auth.static_token]]
            name = "laptop"
            subject = "someone"
            token = "{Secret}"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        // The message says the length and the rule. It must not say the value: this text goes to
        // stderr, gets captured by an init system and shipped wherever the host's logs go, and a
        // short credential quoted in a log is a whole credential to whoever reads it.
        Assert.DoesNotContain(Secret, problem.Message, StringComparison.Ordinal);
        Assert.Contains(problem.Problems, p => p.Contains("7 characters", StringComparison.Ordinal));
    }

    [Fact]
    public void A_long_enough_token_is_accepted()
    {
        // Control for the rule above.
        using var file = TempConfigFile.Write(Minimal);

        Assert.Equal(Token, ConfigurationLoader.Load(file.Path).Configuration.Auth.StaticTokens[0].Token);
    }

    [Fact]
    public void Two_tokens_with_the_same_name_are_refused()
    {
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "static-token"

            [[auth.static_token]]
            name = "laptop"
            subject = "someone"
            token = "0123456789012345678901234567890123456789"

            [[auth.static_token]]
            name = "laptop"
            subject = "someone-else"
            token = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains("already uses", StringComparison.Ordinal));
    }

    [Fact]
    public void Two_tokens_for_one_subject_are_allowed()
    {
        // Two credentials for one person is a deliberate arrangement, not a mistake. The uniqueness
        // rule is on the name, which is what the audit record has to tell apart.
        using var file = TempConfigFile.Write("""
            [auth]
            mode = "static-token"

            [[auth.static_token]]
            name = "laptop"
            subject = "someone"
            token = "0123456789012345678901234567890123456789"

            [[auth.static_token]]
            name = "ci"
            subject = "someone"
            token = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn"
            """);

        Assert.Equal(2, ConfigurationLoader.Load(file.Path).Configuration.Auth.StaticTokens.Count);
    }

    [Fact]
    public void A_non_loopback_listen_address_warns_rather_than_refusing()
    {
        using var file = TempConfigFile.Write("""
            [server]
            listen = "0.0.0.0:8760"

            [auth]
            mode = "static-token"

            [[auth.static_token]]
            name = "laptop"
            subject = "someone"
            token = "0123456789012345678901234567890123456789"
            """);

        var loaded = ConfigurationLoader.Load(file.Path);

        // A warning, not a refusal: binding publicly is a real deployment choice, and one this
        // cannot make for the operator. What it can do is make sure nobody arrives there silently.
        Assert.Contains(loaded.Warnings, w => w.Contains("not loopback", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("127.0.0.1:8760")]
    [InlineData("localhost:8760")]
    [InlineData("[::1]:8760")]
    public void A_loopback_listen_address_is_not_warned_about(string listen)
    {
        using var file = TempConfigFile.Write($"""
            [server]
            listen = "{listen}"

            [auth]
            mode = "static-token"

            [[auth.static_token]]
            name = "laptop"
            subject = "someone"
            token = "0123456789012345678901234567890123456789"
            """);

        Assert.DoesNotContain(
            ConfigurationLoader.Load(file.Path).Warnings,
            w => w.Contains("not loopback", StringComparison.Ordinal));
    }

    [Fact]
    public void A_syntax_error_is_refused_with_its_position()
    {
        using var file = TempConfigFile.Write("[auth\nmode = \"static-token\"\n");

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        // The file it was reading and where in it, so the operator can go straight there rather
        // than diffing the file against the documentation.
        Assert.Contains(problem.Problems, p => p.Contains(file.Path, StringComparison.Ordinal));
        Assert.Contains(problem.Problems, p => p.Contains("(1,", StringComparison.Ordinal));
    }
}
