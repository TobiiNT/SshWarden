using SshWarden.Configuration;

using Xunit;

namespace SshWarden.Tests;

public sealed class GrantConfigurationTests
{
    private const string Auth = """
        [auth]
        mode = "static-token"

        [[auth.static_token]]
        name = "laptop"
        subject = "someone"
        token = "0123456789012345678901234567890123456789"
        """;

    private const string Ssh = """
        [ssh]
        identity_file = "{identity_file}"

        [[host]]
        name = "dev-web-1"
        fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        """;

    [Fact]
    public void A_complete_file_loads()
    {
        using var file = TempConfigFile.Write($"""
            {Auth}

            {Ssh}

            [[grant]]
            id = "dev-exec"
            subject = "someone"
            scopes = ["ssh:exec"]
            tools = ["run"]
            hosts = ["dev-*"]
            ssh_user = "deploy"
            """);

        var configuration = ConfigurationLoader.Load(file.Path).Configuration;

        var grant = Assert.Single(configuration.Grants);
        Assert.Equal("dev-exec", grant.Id);
        Assert.Equal("deploy", grant.SshUser);
        Assert.Equal(22, Assert.Single(configuration.Hosts).Port);
        Assert.Equal(60, configuration.Ssh!.DefaultTimeoutSeconds);
    }

    [Fact]
    public void A_grant_with_no_id_is_refused()
    {
        // The id goes into the audit record as the rule that decided, which is what a dashboard
        // query matches on. Deriving it from the block's position would renumber every saved query
        // the moment somebody inserts a rule above it.
        var problems = Refuse($"""
            {Auth}

            {Ssh}

            [[grant]]
            subject = "someone"
            tools = ["run"]
            hosts = ["dev-*"]
            ssh_user = "deploy"
            """);

        Assert.Contains(problems, p => p.Contains("grant[0].id is not set", StringComparison.Ordinal));
    }

    [Fact]
    public void A_grant_naming_a_tool_that_does_not_exist_is_refused()
    {
        var problems = Refuse($"""
            {Auth}

            {Ssh}

            [[grant]]
            id = "typo"
            subject = "someone"
            tools = ["runn"]
            hosts = ["dev-*"]
            ssh_user = "deploy"
            """);

        Assert.Contains(problems, p => p.Contains("'runn', which is not a tool", StringComparison.Ordinal));
    }

    [Fact]
    public void A_grant_declaring_paths_for_a_tool_that_reads_none_is_refused()
    {
        // A selector nothing consults is a line somebody wrote believing it narrowed something.
        // `run` gates on the host alone - its command is behaviour rather than a resource - so a
        // path beside it enforces nothing and reads as though it does.
        var problems = Refuse($"""
            {Auth}

            {Ssh}

            [[grant]]
            id = "reader"
            subject = "someone"
            tools = ["run"]
            hosts = ["dev-*"]
            paths = ["/var/log/**"]
            ssh_user = "auditor"
            """);

        Assert.Contains(problems, p => p.Contains("narrows nothing", StringComparison.Ordinal));
    }

    [Fact]
    public void A_grant_for_read_file_with_no_paths_is_refused()
    {
        // The other direction. Deny-by-default means such a rule refuses every read, which is safe
        // and reads exactly like a rule that works.
        var problems = Refuse($"""
            {Auth}

            {Ssh}

            [[grant]]
            id = "reader"
            subject = "someone"
            tools = ["read_file"]
            hosts = ["dev-*"]
            ssh_user = "auditor"
            """);

        Assert.Contains(problems, p => p.Contains("names no paths", StringComparison.Ordinal));
    }

    [Fact]
    public void A_grant_for_read_file_with_paths_loads()
    {
        // The control for both.
        using var file = TempConfigFile.Write($"""
            {Auth}

            {Ssh}

            [[grant]]
            id = "reader"
            subject = "someone"
            tools = ["read_file", "tail_log"]
            hosts = ["dev-*"]
            paths = ["/var/log/**"]
            units = ["nginx*"]
            ssh_user = "auditor"
            """);

        var grant = Assert.Single(ConfigurationLoader.Load(file.Path).Configuration.Grants);

        Assert.Equal(["/var/log/**"], grant.Paths);
        Assert.Equal(["nginx*"], grant.Units);
    }

    [Theory]
    [InlineData("var/log/**", "is not absolute")]
    [InlineData("/var/../etc/**", "contains '..'")]
    [InlineData("/var/log**", "'**' inside a segment")]
    public void An_unusable_path_pattern_is_refused_with_a_reason(string pattern, string expected)
    {
        var problems = Refuse($"""
            {Auth}

            {Ssh}

            [[grant]]
            id = "reader"
            subject = "someone"
            tools = ["read_file"]
            hosts = ["dev-*"]
            paths = ["{pattern}"]
            ssh_user = "auditor"
            """);

        Assert.Contains(problems, p => p.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void A_unit_pattern_containing_a_slash_is_refused()
    {
        // A caller's argument is read as a path when it starts with '/', so such a rule could never
        // fire - and a rule that cannot match looks exactly like a rule that is working.
        var problems = Refuse($"""
            {Auth}

            {Ssh}

            [[grant]]
            id = "reader"
            subject = "someone"
            tools = ["tail_log"]
            hosts = ["dev-*"]
            units = ["/var/log/syslog"]
            ssh_user = "auditor"
            """);

        Assert.Contains(problems, p => p.Contains("Put it in 'paths'", StringComparison.Ordinal));
    }

    [Fact]
    public void A_host_with_no_fingerprint_is_refused()
    {
        // No trust-on-first-use and no way to turn it off. A connection made without checking the
        // host key hands the private key's authority, and every command, to whoever answered.
        var problems = Refuse($"""
            {Auth}

            [ssh]
            identity_file = "{TempConfigFile.IdentityFilePlaceholder}"

            [[host]]
            name = "dev-web-1"
            """);

        Assert.Contains(problems, p => p.Contains("fingerprint is not set", StringComparison.Ordinal));
    }

    [Fact]
    public void A_host_with_a_malformed_fingerprint_is_refused()
    {
        var problems = Refuse($"""
            {Auth}

            [ssh]
            identity_file = "{TempConfigFile.IdentityFilePlaceholder}"

            [[host]]
            name = "dev-web-1"
            fingerprint = "MD5:d4:1d:8c:d9:8f:00:b2:04:e9:80:09:98:ec:f8:42:7e"
            """);

        Assert.Contains(problems, p => p.Contains("SHA256:", StringComparison.Ordinal));
    }

    [Fact]
    public void Hosts_declared_without_an_ssh_table_are_refused()
    {
        var problems = Refuse($"""
            {Auth}

            [[host]]
            name = "dev-web-1"
            fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            """);

        Assert.Contains(problems, p => p.Contains("no [ssh] table", StringComparison.Ordinal));
    }

    [Fact]
    public void A_grant_reaching_no_declared_host_is_loaded_with_a_warning()
    {
        // A rule that cannot fire. Not refused - hosts get added, and a rule written ahead of the
        // machine it is for is reasonable - but it is also exactly what a typo looks like.
        using var file = TempConfigFile.Write($"""
            {Auth}

            {Ssh}

            [[grant]]
            id = "nowhere"
            subject = "someone"
            tools = ["run"]
            hosts = ["staging-*"]
            ssh_user = "deploy"
            """);

        Assert.Contains(
            ConfigurationLoader.Load(file.Path).Warnings,
            w => w.Contains("matches no declared [[host]]", StringComparison.Ordinal));
    }

    [Fact]
    public void A_default_timeout_above_the_ceiling_is_refused()
    {
        var problems = Refuse($"""
            {Auth}

            [ssh]
            identity_file = "{TempConfigFile.IdentityFilePlaceholder}"
            default_timeout_sec = 1000
            max_timeout_sec = 900
            """);

        Assert.Contains(problems, p => p.Contains("above the ceiling", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unwritable_audit_path_is_refused()
    {
        // The choke point exists so that one place knows what ran where. Running it without the
        // ability to write that down is worse than not running it: the work still happens and the
        // record does not, and nothing about it looks wrong.
        using var file = TempConfigFile.Write($"""
            {Auth}

            [audit]
            path = "/proc/definitely-not-writable/audit.jsonl"
            """);

        var problem = Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path));

        Assert.Contains(problem.Problems, p => p.Contains("cannot be written", StringComparison.Ordinal));
    }

    private static IReadOnlyList<string> Refuse(string content)
    {
        using var file = TempConfigFile.Write(content);
        return Assert.Throws<SshWardenConfigurationException>(
            () => ConfigurationLoader.Load(file.Path)).Problems;
    }
}
