using SshWarden.Ssh;

using Xunit;

namespace SshWarden.Ssh.IntegrationTests;

/// <summary>
/// What the SSH layer does against a real OpenSSH server.
/// </summary>
/// <remarks>
/// Everything here is a claim about somebody else's software - a shell, a server, a library - and
/// none of it is worth asserting against a stand-in. The whole point is that these are measured.
/// </remarks>
public sealed class SshCommandRunnerTests : IClassFixture<LocalSshServerFixture>
{
    private readonly LocalSshServerFixture _server;

    public SshCommandRunnerTests(LocalSshServerFixture server) => _server = server;

    [Fact]
    public async Task A_command_runs_and_reports_its_output_and_status()
    {
        var outcome = await Run("echo hello");

        Assert.Equal(0, outcome.ExitCode);
        Assert.Equal("hello\n", outcome.Stdout);
        Assert.Equal(6, outcome.StdoutBytes);
    }

    [Fact]
    public async Task A_failing_command_reports_its_status_rather_than_failing_the_call()
    {
        // A non-zero exit is a result, not an error. An agent needs to see it and decide; wrapping
        // it as a transport failure would hide which of the two happened.
        var outcome = await Run("exit 3");

        Assert.Equal(3, outcome.ExitCode);
    }

    [Fact]
    public async Task Standard_error_comes_back_separately()
    {
        var outcome = await Run("echo out; echo err >&2");

        Assert.Equal("out\n", outcome.Stdout);
        Assert.Equal("err\n", outcome.Stderr);
    }

    [Fact]
    public async Task No_state_survives_between_commands()
    {
        // The property the whole design rests on. Each command gets a new channel, so a directory
        // change or a variable set by one is not there for the next - which is what makes a single
        // line of the audit log readable on its own.
        _ = await Run("cd /tmp && export MARKER=set");

        var outcome = await Run("pwd; echo \"[${MARKER:-unset}]\"");

        Assert.DoesNotContain("/tmp\n", outcome.Stdout, StringComparison.Ordinal);
        Assert.Contains("[unset]", outcome.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_working_directory_is_where_the_caller_said()
    {
        var outcome = await Run("pwd", workdir: "/tmp");

        Assert.Equal("/tmp\n", outcome.Stdout);
    }

    [Fact]
    public async Task A_working_directory_containing_shell_syntax_is_a_directory_and_not_a_program()
    {
        // The quoting rule, measured against a real shell rather than asserted against a string.
        // The directory does not exist, so the command fails - but it fails as a directory that is
        // not there, and the injected command does not run.
        var outcome = await Run("echo reached", workdir: "/tmp/$(id -u)x'; id; '");

        Assert.NotEqual(0, outcome.ExitCode);
        Assert.DoesNotContain("uid=", outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("uid=", outcome.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("reached", outcome.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Environment_variables_reach_the_command()
    {
        // They are inlined into the command rather than sent as SSH environment requests, because
        // sshd's AcceptEnv defaults to LANG and LC_* - anything else sent that way is dropped in
        // silence, and the command runs without it. This fixture's sshd has that default.
        var outcome = await Run(
            "echo \"$GREETING\"",
            environment: new Dictionary<string, string> { ["GREETING"] = "well hello" });

        Assert.Equal("well hello\n", outcome.Stdout);
    }

    [Fact]
    public async Task An_environment_value_containing_shell_syntax_arrives_literally()
    {
        var outcome = await Run(
            "echo \"$VALUE\"",
            environment: new Dictionary<string, string> { ["VALUE"] = "$(id -u); rm -rf /" });

        Assert.Equal("$(id -u); rm -rf /\n", outcome.Stdout);
    }

    [Fact]
    public async Task A_command_that_outlasts_its_timeout_is_killed_on_the_far_side()
    {
        // The measurement that decides where the timeout lives. The library's own documentation
        // says a server that does not implement signals may send no response to a cancellation, so
        // cancelling from this side can complete here while the process keeps running there. The
        // timeout is built into the command line instead, and this is what proves it fires.
        var outcome = await Run("sleep 30", timeoutSeconds: 1);

        // 124 is what GNU timeout reports when it had to kill the command. A real answer, and much
        // better than the null an abandoned channel would leave.
        Assert.Equal(124, outcome.ExitCode);
        Assert.True(outcome.DurationMs < 20_000, $"took {outcome.DurationMs}ms");
    }

    [Fact]
    public async Task A_whole_pipeline_is_under_the_timeout()
    {
        // 'timeout N cmd | other' would bound only the first stage. This is why the command is
        // wrapped in sh -c as a single argument.
        var outcome = await Run("sleep 30 | cat", timeoutSeconds: 1);

        Assert.Equal(124, outcome.ExitCode);
    }

    [Fact]
    public async Task Commands_run_concurrently_over_one_pooled_connection()
    {
        // docs/DESIGN.md §4.1 asks for this measurement by name, because the library's README claims
        // it is "optimized for parallelism" without committing to thread safety in writing - which
        // made it unmeasured rather than absent.
        //
        // Measured 2026-08-26 against OpenSSH on loopback, SSH.NET 2026.0.0, .NET 10: sixteen
        // commands issued at once over a single pooled SshClient all completed, each returning its
        // own output. Sixteen is above the default MaxSessions of 10 on purpose, so the session
        // semaphore is doing real work rather than the test fitting under the limit.
        const int Count = 16;

        var results = await Task.WhenAll(
            Enumerable.Range(0, Count).Select(index => Run($"echo {index}")));

        Assert.All(results, outcome => Assert.Equal(0, outcome.ExitCode));
        Assert.Equal(
            [.. Enumerable.Range(0, Count).Select(index => index + "\n")],
            [.. results.Select(outcome => outcome.Stdout)]);
    }

    private Task<CommandOutcome> Run(
        string command,
        string? workdir = null,
        IReadOnlyDictionary<string, string>? environment = null,
        int timeoutSeconds = 30)
        => _server.Runner.RunAsync(
            _server.Server.AsHostEntry(),
            _server.Server.User,
            command,
            workdir,
            environment,
            timeoutSeconds,
            CancellationToken.None);
}

/// <summary>Holds one server and one pool for a whole test class.</summary>
/// <remarks>
/// Shared on purpose. Starting an sshd per test would be slow, and - more usefully - a pool that is
/// torn down between tests would never be asked to hand the same connection back twice, which is
/// the thing it exists to do.
/// </remarks>
public sealed class LocalSshServerFixture : IAsyncDisposable
{
    public LocalSshServerFixture()
    {
        Server = LocalSshServer.Start();
        Pool = new SshConnectionPool(Server.Options);
        Runner = new SshCommandRunner(Pool);
    }

    public LocalSshServer Server { get; }

    public SshConnectionPool Pool { get; }

    public SshCommandRunner Runner { get; }

    public async ValueTask DisposeAsync()
    {
        await Pool.DisposeAsync();
        Server.Dispose();
    }
}
