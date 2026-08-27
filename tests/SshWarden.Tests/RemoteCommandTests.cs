using SshWarden.Ssh;

using Xunit;

namespace SshWarden.Tests;

public sealed class RemoteCommandTests
{
    [Fact]
    public void A_command_with_no_workdir_still_changes_directory_explicitly()
    {
        // There is no session, so there is no "wherever the last command left it" - and an audit
        // record that cannot say where a command ran is the failure this whole design is about.
        var line = RemoteCommand.Build("ls", workdir: null, environment: null, timeoutSeconds: 30);

        Assert.StartsWith("cd -- \"$HOME\" &&", line, StringComparison.Ordinal);
    }

    [Fact]
    public void A_workdir_is_quoted_and_ends_the_options()
    {
        var line = RemoteCommand.Build("ls", "/opt/my app", environment: null, timeoutSeconds: 30);

        Assert.StartsWith("cd -- '/opt/my app' &&", line, StringComparison.Ordinal);
    }

    [Fact]
    public void A_hostile_workdir_cannot_escape_into_the_command()
    {
        // The workdir comes from an agent. It names a place; it is not meant to be a program, and
        // this is the boundary that keeps it from becoming one.
        const string Hostile = "/tmp'; id; '";

        var line = RemoteCommand.Build("ls", Hostile, environment: null, timeoutSeconds: 30);

        // The whole directory arrives as one quoted word and nothing else. Asserting the exact
        // segment rather than "does not contain id" on purpose: the characters are still in there,
        // as they must be, and what matters is that they are inside the quotes rather than outside.
        var directoryChange = line.Split(" && ")[0];
        Assert.Equal("cd -- " + ShellQuoting.Quote(Hostile), directoryChange);
    }

    [Fact]
    public void The_command_is_passed_through_unchanged()
    {
        // Deliberate, and permanent. It is meant to be a shell command - pipes, redirection and all
        // - and filtering it by content is not answerable at the string level. Everything else this
        // builder splices in is quoted precisely because this one is not.
        var line = RemoteCommand.Build("ps aux | grep -v grep | wc -l", null, null, 30);

        Assert.Contains(ShellQuoting.Quote("ps aux | grep -v grep | wc -l"), line, StringComparison.Ordinal);
    }

    [Fact]
    public void The_whole_command_runs_under_the_timeout()
    {
        // 'timeout N cmd | other' would put only the first stage of a pipeline under the timeout
        // and leave the rest unbounded. Wrapping in sh -c with the command as one argument is what
        // makes the limit cover all of it.
        var line = RemoteCommand.Build("sleep 1 | cat", null, null, 30);

        Assert.Contains("timeout -k 5s 30s sh -c '", line, StringComparison.Ordinal);
    }

    [Fact]
    public void Environment_variables_are_inlined_and_quoted()
    {
        // Sent inline rather than through the SSH protocol's environment request: sshd's AcceptEnv
        // defaults to LANG and LC_* only, so a variable sent that way is silently dropped - the
        // command runs, and runs without it.
        var line = RemoteCommand.Build(
            "printenv",
            null,
            new Dictionary<string, string> { ["TOKEN"] = "a b'c" },
            30);

        Assert.Contains("env -- 'TOKEN=a b'\\''c'", line, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("A=B")]
    [InlineData("has space")]
    [InlineData("1FIRST")]
    public void An_unusable_environment_name_is_refused_rather_than_quoted(string name)
    {
        // Quoting does not help: env splits NAME=VALUE on the first '=' itself, so 'A=B' would set
        // a different variable than the one asked for however the word is quoted for the shell.
        var failure = Assert.Throws<ArgumentException>(
            () => RemoteCommand.Build("true", null, new Dictionary<string, string> { [name] = "x" }, 30));

        Assert.Contains(name, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_usable_environment_name_is_accepted()
    {
        // Control for the refusals above.
        var line = RemoteCommand.Build("true", null, new Dictionary<string, string> { ["PATH_EXTRA"] = "x" }, 30);

        Assert.Contains("'PATH_EXTRA=x'", line, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_command_with_no_positive_timeout_is_refused(int timeout)
    {
        // There is always a timeout. Without one the limit is enforced nowhere - and because it is
        // enforced on the remote side, no limit also means no exit status to record when the
        // command never finishes.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => RemoteCommand.Build("true", null, null, timeout));
    }
}
