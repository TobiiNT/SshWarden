using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SshWarden.Authorization;
using SshWarden.Changes;
using SshWarden.Configuration;
using SshWarden.Jobs;
using SshWarden.Mcp;

using Xunit;

namespace SshWarden.Ssh.IntegrationTests;

/// <summary>
/// A tool call arriving over HTTP, running on a real server, and landing in the audit log.
/// </summary>
/// <remarks>
/// The only tests that cover the joins. Each layer is checked on its own elsewhere; what is
/// checked here is what happens between them - and in particular the two things that only show up
/// when real output meets the pipeline: that a secret in what a host printed does not reach the
/// caller, and that a secret the caller passed in does not reach the log.
/// </remarks>
public sealed class EndToEndTests : IAsyncLifetime
{
    private const string Token = "0123456789012345678901234567890123456789";
    private const string OtherToken = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn";

    private LocalSshServer _server = null!;
    private string _allowed = null!;
    private string _offLimits = null!;
    private ChangeSweeper _sweeper = null!;
    private ChangeTimeline _timeline = null!;
    private IHost _host = null!;
    private HttpClient _client = null!;
    private string _auditPath = null!;
    private string _directory = null!;
    private string _remoteJobs = null!;

    public async Task InitializeAsync()
    {
        _server = LocalSshServer.Start();

        _directory = Path.Combine(Path.GetTempPath(), "sshwarden-e2e", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_directory);
        _auditPath = Path.Combine(_directory, "audit.jsonl");

        // A tree the rule allows, and a file outside it. The interesting part is the symlink from
        // inside to outside: every check that can be made from this side passes, and the read lands
        // where no rule covers.
        _allowed = Path.Combine(_directory, "allowed");
        Directory.CreateDirectory(_allowed);
        await File.WriteAllTextAsync(Path.Combine(_allowed, "app.log"), "line one\nline two\n");

        _offLimits = Path.Combine(_directory, "secrets.env");
        await File.WriteAllTextAsync(_offLimits, "API_TOKEN=ghp_0123456789012345678901234567890123456\n");

        File.CreateSymbolicLink(Path.Combine(_allowed, "innocent.log"), _offLimits);

        var configuration = new SshWardenConfiguration
        {
            Server = new ServerSection(),
            Auth = new AuthSection
            {
                Mode = AuthModes.StaticToken,
                StaticTokens = [
                    new StaticTokenEntry { Name = "test", Subject = "tester", Token = Token },
                    new StaticTokenEntry { Name = "other", Subject = "somebody-else", Token = OtherToken },
                ],
            },
            Ssh = _server.Options,
            Hosts = [_server.AsHostEntry()],
            Grants = [
                new Grant
                {
                    Id = "everything",
                    Subject = "tester",
                    Tools = ["run", "list_changes", "start_job", "poll_job", "kill_job"],
                    Hosts = ["local-test"],
                    SshUser = _server.User,
                },
                new Grant
                {
                    // The same reach for a different subject. Everything except ownership is equal
                    // between these two, which is what makes the ownership test about ownership.
                    Id = "everything-else",
                    Subject = "somebody-else",
                    Tools = ["run", "list_changes", "start_job", "poll_job", "kill_job"],
                    Hosts = ["local-test"],
                    SshUser = _server.User,
                },
                new Grant
                {
                    Id = "logs",
                    Subject = "tester",
                    Tools = ["read_file", "tail_log"],
                    Hosts = ["local-test"],
                    Paths = [_allowed + "/**"],
                    SshUser = _server.User,
                },
            ],
            Audit = new AuditSection { Path = _auditPath },
            Jobs = new JobsSection
            {
                Registry = Path.Combine(Path.GetDirectoryName(_auditPath)!, "jobs.jsonl"),
            },
            Metrics = new MetricsSection(),
            Output = new OutputSection { MaxBytes = 2048 },

            // A long interval, because these tests drive the sweeper themselves rather than waiting
            // for it. Waiting on a timer is how a suite becomes slow and flaky at the same time.
            Watch = new WatchSection
            {
                Paths = [_allowed],
                IntervalSeconds = 3600,
                RetentionMinutes = 60,
            },
        };

        // Read off the configuration rather than repeated as a literal, so a test that goes looking
        // for a job's directory on disk looks where this deployment actually puts it.
        _remoteJobs = configuration.Jobs.RemoteDirectory;

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddSshWarden(configuration);

        var app = builder.Build();
        app.UseRouting();
        app.UseSshWardenAuthentication();
        app.MapSshWardenHealth();
        app.MapSshWarden(configuration);

        await app.StartAsync();

        _host = app;
        _client = app.GetTestClient();
        _sweeper = app.Services.GetRequiredService<ChangeSweeper>();
        _timeline = app.Services.GetRequiredService<ChangeTimeline>();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
        _server.Dispose();

        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // Untidy, not broken.
        }
    }

    [Fact]
    public async Task A_command_runs_and_the_call_is_recorded()
    {
        var result = await Run(new { host = "local-test", cmd = "echo hello" });

        Assert.Equal(0, result.GetProperty("exit_code").GetInt32());
        Assert.Equal("hello\n", result.GetProperty("stdout").GetString());
        Assert.False(result.GetProperty("output_truncated").GetBoolean());

        var record = Assert.Single(Records());
        Assert.Equal("allow", record.GetProperty("decision").GetString());
        Assert.Equal("everything", record.GetProperty("allowed_by").GetString());
        Assert.Equal(_server.User, record.GetProperty("ssh_user").GetString());
        Assert.Equal(0, record.GetProperty("exit_code").GetInt32());
    }

    [Fact]
    public async Task A_secret_the_host_printed_does_not_reach_the_caller()
    {
        // The failure this is for: an agent runs `cat .env`, the key lands in its context, and from
        // there in whatever transcript its provider keeps. Nothing downstream can take that back.
        var result = await Run(new
        {
            host = "local-test",
            cmd = "echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIexamplekey'; echo AKIAIOSFODNN7EXAMPLE",
        });

        var stdout = result.GetProperty("stdout").GetString()!;

        Assert.DoesNotContain("wJalrXUtnFEMIexamplekey", stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", stdout, StringComparison.Ordinal);
        Assert.Equal(2, result.GetProperty("redacted_values").GetInt32());

        // The variable name survives, so the output still tells the reader what was there.
        Assert.Contains("AWS_SECRET_ACCESS_KEY", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_secret_the_caller_passed_in_does_not_reach_the_audit_log()
    {
        // A hole step 2 left open. Environment variables have to be inlined into the command string
        // - sshd drops variables sent through the protocol - so a caller passing a token as an
        // environment variable put it verbatim into the recorded command line. The audit log is the
        // one artefact of this project that gets shipped somewhere else.
        const string Secret = "ghp_0123456789012345678901234567890123456";

        _ = await Run(new
        {
            host = "local-test",
            cmd = "true",
            env = new Dictionary<string, string> { ["GITHUB_TOKEN"] = Secret },
        });

        var record = Assert.Single(Records());
        var command = record.GetProperty("command").GetString()!;

        Assert.DoesNotContain(Secret, command, StringComparison.Ordinal);
        Assert.DoesNotContain("ghp_", command, StringComparison.Ordinal);

        // The rest of the command line stays, because reproducing what ran is what the field is for.
        Assert.Contains("timeout", command, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Output_over_the_budget_comes_back_cut_and_says_so()
    {
        var result = await Run(new { host = "local-test", cmd = "seq 1 20000" });

        var stdout = result.GetProperty("stdout").GetString()!;

        Assert.True(result.GetProperty("output_truncated").GetBoolean());
        Assert.Contains("SshWarden truncated", stdout, StringComparison.Ordinal);

        // Both ends kept: the head says what it was doing, the tail says how it ended.
        Assert.Contains("\n1\n", "\n" + stdout, StringComparison.Ordinal);
        Assert.Contains("20000", stdout, StringComparison.Ordinal);

        // And the record still carries what the host produced, not what the caller received.
        var record = Assert.Single(Records());
        Assert.True(record.GetProperty("stdout_bytes").GetInt64() > 100_000);
        Assert.True(record.GetProperty("output_truncated").GetBoolean());
    }

    [Fact]
    public async Task Grep_filters_before_the_budget_so_the_answer_is_the_lines_asked_for()
    {
        // Without the filter this output would be truncated; with it, the caller gets every line it
        // asked for and nothing is dropped. That is the point of filtering server-side rather than
        // making the agent re-run with a narrower command.
        var result = await Run(new { host = "local-test", cmd = "seq 1 20000", grep = "^1234$" });

        Assert.Equal("1234", result.GetProperty("stdout").GetString());
        Assert.False(result.GetProperty("output_truncated").GetBoolean());

        // Measured on what the host produced, whatever the filter kept.
        Assert.True(Assert.Single(Records()).GetProperty("stdout_bytes").GetInt64() > 100_000);
    }

    [Fact]
    public async Task An_unusable_grep_pattern_is_reported_rather_than_ignored()
    {
        var result = await Run(new { host = "local-test", cmd = "echo alpha", grep = "(unclosed" });

        var notes = result.GetProperty("notes").EnumerateArray().Select(note => note.GetString()!).ToList();

        Assert.NotEmpty(notes);
        Assert.Contains(notes, note => note.Contains("grep pattern", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_file_inside_the_allowed_tree_is_read()
    {
        // The control for everything below.
        var result = await Call("read_file", new { host = "local-test", path = Path.Combine(_allowed, "app.log") });

        Assert.Equal("line one\nline two\n", result.GetProperty("content").GetString());

        var record = Assert.Single(Records());
        Assert.Equal("allow", record.GetProperty("decision").GetString());
        Assert.Equal("logs", record.GetProperty("allowed_by").GetString());
    }

    [Fact]
    public async Task A_symlink_out_of_the_allowed_tree_is_refused_after_the_target_resolves_it()
    {
        // **The trap the whole path gate exists for.** The caller names a file that sits inside an
        // allowed directory. It is absolute, it has no '..' in it, and it matches the rule - every
        // check that can be made from this side passes. On the target it is a symlink to a file no
        // rule covers, and only asking the target resolves that.
        var refusal = await CallExpectingRefusal(
            "read_file",
            new { host = "local-test", path = Path.Combine(_allowed, "innocent.log") });

        Assert.Contains("path_escapes_grant", refusal, StringComparison.Ordinal);

        // The content never came back.
        Assert.DoesNotContain("ghp_", refusal, StringComparison.Ordinal);

        // And the record carries both halves. A refusal naming a rule and nothing else gives
        // whoever reads it nothing to act on: the point is that these two differ.
        var record = Assert.Single(Records());
        Assert.Equal("path_escapes_grant", record.GetProperty("denied_by").GetString());
        Assert.Equal(Path.Combine(_allowed, "innocent.log"), record.GetProperty("selector").GetString());
        Assert.Equal(_offLimits, record.GetProperty("resolved_path").GetString());
    }

    [Fact]
    public async Task The_file_that_is_opened_is_the_resolved_one_and_the_record_says_which()
    {
        // A symlink that stays inside the allowed tree, so the call succeeds - and the point is
        // *which* path the read command names. Reading the caller's path re-traverses the symlink
        // at read time, which is a second chance for it to point somewhere else; reading what
        // realpath returned cannot be redirected, because realpath returns a path with no symlink
        // components left in it. That is the only part of the time-of-check gap that can be closed
        // from here, and closing it costs nothing.
        var real = Path.Combine(_allowed, "app-2.log");
        await File.WriteAllTextAsync(real, "the real one\n");

        var link = Path.Combine(_allowed, "current.log");
        File.CreateSymbolicLink(link, real);

        var result = await Call("read_file", new { host = "local-test", path = link });

        Assert.Equal("the real one\n", result.GetProperty("content").GetString());
        Assert.Equal(real, result.GetProperty("path").GetString());
        Assert.Equal(link, result.GetProperty("requested_path").GetString());

        var record = Assert.Single(Records());
        Assert.Equal(link, record.GetProperty("selector").GetString());
        Assert.Equal(real, record.GetProperty("resolved_path").GetString());

        // And the command that ran names the resolved file, not the link. A record that says a link
        // was read leaves the reader to guess what was behind it.
        Assert.Contains(real, record.GetProperty("command").GetString()!, StringComparison.Ordinal);
        Assert.DoesNotContain(link, record.GetProperty("command").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_path_containing_dot_dot_is_refused_before_the_target_is_touched()
    {
        var refusal = await CallExpectingRefusal(
            "read_file",
            new { host = "local-test", path = _allowed + "/../secrets.env" });

        Assert.Contains("'..'", refusal, StringComparison.Ordinal);

        var record = Assert.Single(Records());
        Assert.Equal("path_not_usable", record.GetProperty("denied_by").GetString());

        // The path is on the record even though no rule was consulted. A line saying "a path was
        // refused as unusable" without saying which path is one nobody can act on.
        Assert.Equal(_allowed + "/../secrets.env", record.GetProperty("selector").GetString());

        // And nothing was resolved, because nothing was asked of the target.
        Assert.Equal(JsonValueKind.Null, record.GetProperty("resolved_path").ValueKind);
    }

    [Fact]
    public async Task A_path_outside_the_allowed_tree_is_refused_without_asking_the_target()
    {
        var refusal = await CallExpectingRefusal(
            "read_file",
            new { host = "local-test", path = _offLimits });

        Assert.Contains("path_not_granted", refusal, StringComparison.Ordinal);
        Assert.Equal("path_not_granted", Assert.Single(Records()).GetProperty("denied_by").GetString());
    }

    [Fact]
    public async Task A_missing_file_is_reported_as_missing_rather_than_refused()
    {
        // Reporting a typo as a permission problem sends somebody to edit the grant table over
        // nothing.
        var refusal = await CallExpectingRefusal(
            "read_file",
            new { host = "local-test", path = Path.Combine(_allowed, "absent.log") });

        Assert.Contains("no such file", refusal, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("path_not_found", Assert.Single(Records()).GetProperty("denied_by").GetString());
    }

    [Fact]
    public async Task A_secret_in_a_file_that_is_read_is_masked()
    {
        var inside = Path.Combine(_allowed, "config.env");
        await File.WriteAllTextAsync(inside, "API_TOKEN=ghp_0123456789012345678901234567890123456\n");

        var result = await Call("read_file", new { host = "local-test", path = inside });

        var content = result.GetProperty("content").GetString()!;
        Assert.DoesNotContain("ghp_", content, StringComparison.Ordinal);
        Assert.Contains("API_TOKEN", content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Tail_log_reads_the_end_of_a_file_inside_the_tree()
    {
        var log = Path.Combine(_allowed, "many.log");
        await File.WriteAllLinesAsync(log, Enumerable.Range(1, 500).Select(index => $"entry {index}"));

        var result = await Call("tail_log", new { host = "local-test", unitOrPath = log, lines = 3 });

        Assert.Equal("entry 498\nentry 499\nentry 500\n", result.GetProperty("lines").GetString());
    }

    [Fact]
    public async Task Tail_log_refuses_a_unit_no_rule_covers()
    {
        // The rule names paths and no units, so every unit is refused - deny by default, with the
        // identifier saying which selector was the problem rather than a bare "denied".
        var refusal = await CallExpectingRefusal(
            "tail_log",
            new { host = "local-test", unitOrPath = "nginx.service" });

        Assert.Contains("unit_not_granted", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_sweep_notices_a_real_file_appearing_and_changing()
    {
        // Against a real filesystem through a real SSH connection, because everything this
        // mechanism claims is about what `find` prints and what stat fields do.
        _ = await Run(new { host = "local-test", cmd = "true" });   // opens the connection to sweep over

        Assert.Equal(1, await _sweeper.SweepOnceAsync(CancellationToken.None));

        // The first sweep is a baseline. Reporting the whole tree as created files would fill the
        // timeline with an event that did not happen.
        Assert.Empty(_timeline.Since("local-test", TimeSpan.FromMinutes(10), DateTimeOffset.UtcNow));

        var created = Path.Combine(_allowed, "brand-new.conf");
        await File.WriteAllTextAsync(created, "first\n");

        _ = await _sweeper.SweepOnceAsync(CancellationToken.None);

        var afterCreate = _timeline.Since("local-test", TimeSpan.FromMinutes(10), DateTimeOffset.UtcNow);
        var creation = Assert.Single(afterCreate, change => change.Path == created);
        Assert.Equal(FileChangeKinds.Created, creation.Kind);

        await File.WriteAllTextAsync(created, "second, and longer\n");
        _ = await _sweeper.SweepOnceAsync(CancellationToken.None);

        Assert.Contains(
            _timeline.Since("local-test", TimeSpan.FromMinutes(10), DateTimeOffset.UtcNow),
            change => change.Path == created && change.Kind == FileChangeKinds.Modified);

        File.Delete(created);
        _ = await _sweeper.SweepOnceAsync(CancellationToken.None);

        Assert.Contains(
            _timeline.Since("local-test", TimeSpan.FromMinutes(10), DateTimeOffset.UtcNow),
            change => change.Path == created && change.Kind == FileChangeKinds.Deleted);
    }

    [Fact]
    public async Task A_host_with_no_live_connection_is_not_swept()
    {
        // The rule that keeps an idle host free. Sweeping a machine nobody is working on costs a
        // session on its sshd and produces timeline entries that read as activity.
        Assert.Equal(0, await _sweeper.SweepOnceAsync(CancellationToken.None));
    }

    [Fact]
    public async Task List_changes_reports_what_the_sweeper_saw()
    {
        _ = await Run(new { host = "local-test", cmd = "true" });
        _ = await _sweeper.SweepOnceAsync(CancellationToken.None);

        var touched = Path.Combine(_allowed, "watched.conf");
        await File.WriteAllTextAsync(touched, "changed\n");
        _ = await _sweeper.SweepOnceAsync(CancellationToken.None);

        var result = await Call("list_changes", new { host = "local-test", sinceMinutes = 10 });

        Assert.Contains(
            result.GetProperty("changes").EnumerateArray(),
            change => change.GetProperty("path").GetString() == touched);

        Assert.Empty(result.GetProperty("notes").EnumerateArray());
    }

    [Fact]
    public async Task List_changes_says_when_a_host_has_never_been_swept()
    {
        // Empty because nothing was looked at, not because nothing changed - and the answer has to
        // carry that difference or a caller reads a confident zero.
        var result = await Call("list_changes", new { host = "local-test" });

        Assert.Empty(result.GetProperty("changes").EnumerateArray());
        Assert.Contains(
            result.GetProperty("notes").EnumerateArray().Select(note => note.GetString()!),
            note => note.Contains("has not been swept yet", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_command_record_says_how_much_of_it_was_actually_looked_at()
    {
        _ = await Run(new { host = "local-test", cmd = "true" });
        _ = await _sweeper.SweepOnceAsync(CancellationToken.None);

        var first = Records();

        // A command whose window no sweep has closed yet: zero, and an empty list the zero explains.
        Assert.Equal(0, first[0].GetProperty("changes_window_ms").GetInt64());
        Assert.Empty(first[0].GetProperty("changes").EnumerateArray());
        Assert.Equal(CommandOverlap.Exclusive, first[0].GetProperty("changes_confidence").GetString());

        // Now a command a sweep lands inside. The record is written when the command ends, so a
        // window wider than zero needs a sweep that happened while it was still running - which is
        // the ordinary case for anything slower than the interval, and the case worth proving.
        //
        // Sequenced on a marker the command itself creates rather than on a delay: waiting on the
        // work is deterministic, waiting on a clock is a flake looking for a loaded machine.
        var marker = Path.Combine(_directory, "started");
        var written = Path.Combine(_allowed, "by-the-command.conf");

        var running = Run(new
        {
            host = "local-test",
            cmd = $"touch {marker}; printf x > {written}; sleep 3",
            timeoutSec = 30,
        });

        while (!File.Exists(marker))
        {
            await Task.Yield();
        }

        _ = await _sweeper.SweepOnceAsync(CancellationToken.None);
        _ = await running;

        var covered = Records()[^1];

        Assert.True(
            covered.GetProperty("changes_window_ms").GetInt64() > 0,
            "the sweep inside the command should have widened its window past zero");

        Assert.Equal(CommandOverlap.Exclusive, covered.GetProperty("changes_confidence").GetString());

        // And the file the command wrote is on its record.
        Assert.Contains(
            covered.GetProperty("changes").EnumerateArray(),
            change => change.GetProperty("path").GetString() == written);
    }

    [Fact]
    public async Task A_job_outlives_the_call_that_started_it()
    {
        // The whole point of a job rather than a command: `run` waits, this does not. The command
        // here would time out as a `run`; as a job the call returns immediately and the process
        // keeps going on the target.
        var gate = Path.Combine(_directory, "job-gate");

        var started = await Call("start_job", new
        {
            host = "local-test",

            // Held at a gate the test opens, rather than at a sleep. What is being proved is that
            // the second poll returns only what appeared since the first, and a job that can finish
            // before the first poll lands proves that by accident or not at all - which is how this
            // test passed for a while against a `start_job` that returned before the job existed.
            cmd = $"echo first; while [ ! -f {gate} ]; do sleep 0.05; done; echo second",
        });

        var jobId = started.GetProperty("job_id").GetString()!;
        Assert.StartsWith("sw_job_", jobId, StringComparison.Ordinal);

        // Waiting on the work rather than on a clock: the first line has been printed and the job
        // is now held, so this poll catches it mid-flight every time.
        JsonElement first;
        do
        {
            first = await Call("poll_job", new { jobId, sinceLine = 0 });
        }
        while (first.GetProperty("output").GetString()!.Length == 0);

        Assert.Equal(JobStatuses.Running, first.GetProperty("status").GetString());
        Assert.Contains("first", first.GetProperty("output").GetString()!, StringComparison.Ordinal);

        var nextLine = first.GetProperty("next_line").GetInt32();

        // Only now can it reach its second line, so the second poll is what proves paging works: it
        // must return what appeared since the first and not the whole file again.
        File.WriteAllText(gate, string.Empty);

        JsonElement second;
        do
        {
            second = await Call("poll_job", new { jobId, sinceLine = nextLine });
        }
        while (second.GetProperty("status").GetString() == JobStatuses.Running);

        Assert.Equal(JobStatuses.Finished, second.GetProperty("status").GetString());
        Assert.Equal(0, second.GetProperty("exit_code").GetInt32());
        Assert.Contains("second", second.GetProperty("output").GetString()!, StringComparison.Ordinal);
        Assert.DoesNotContain("first", second.GetProperty("output").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_job_command_containing_quotes_survives_the_wrapper()
    {
        // The nesting question a string assertion cannot settle: the caller's command goes inside a
        // shell string that is itself inside another. Only a real shell says whether it came out
        // the other side as one command or as two.
        var started = await Call("start_job", new
        {
            host = "local-test",
            // Verbatim, and that is the point of the comment: written as an ordinary C# string this
            // read `"echo 'it'\''s fine'"`, where C# eats the backslash and sends five single
            // quotes where four were meant. The target answered `Unterminated quoted string` and it
            // was right - the test was wrong, and it took the wrapper's stderr to show it.
            cmd = @"echo 'it'\''s fine'; echo second-line",
        });

        var jobId = started.GetProperty("job_id").GetString()!;

        JsonElement polled;
        do
        {
            polled = await Call("poll_job", new { jobId, sinceLine = 0 });
        }
        while (polled.GetProperty("status").GetString() == JobStatuses.Running);

        Assert.Equal("it's fine\nsecond-line\n", polled.GetProperty("output").GetString());
    }

    [Fact]
    public async Task A_job_that_cannot_start_is_refused_rather_than_accepted()
    {
        // The half of the wait that is observable. Without it `start_job` returns before the job
        // exists, so a command the target's shell cannot even parse is accepted, an identifier is
        // handed back for a job that will never run, and the caller finds out at some later poll -
        // as `gone`, with no output and nothing saying why. With it the shell's own complaint comes
        // back from the call that caused it.
        //
        // The control is A_job_command_containing_quotes_survives_the_wrapper: a command with the
        // same quoting that is valid starts and runs.
        var refusal = await CallExpectingRefusal("start_job", new
        {
            host = "local-test",
            cmd = "echo 'unterminated",
        });

        Assert.Contains("did not start", refusal, StringComparison.Ordinal);

        // Verbatim from the target rather than reworded here. Which line of a nested wrapper the
        // shell is complaining about is the only thing that locates a quoting fault, and this
        // server is not the one that can tell.
        Assert.Contains("Syntax error", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_job_is_killed_as_a_whole_process_group()
    {
        // Killing only the leader of a pipeline leaves the rest running and reports success, so the
        // job is given its own process group and the signal goes to the group.
        var started = await Call("start_job", new
        {
            host = "local-test",
            cmd = "sleep 300 | cat",
        });

        var jobId = started.GetProperty("job_id").GetString()!;

        _ = await Call("kill_job", new { jobId });

        var polled = await Call("poll_job", new { jobId, sinceLine = 0 });

        // Gone rather than finished: it left no exit status, and reporting it as finished with an
        // unknown code would say the command completed when it did not.
        Assert.Equal(JobStatuses.Gone, polled.GetProperty("status").GetString());
    }

    [Fact]
    public async Task A_job_that_finishes_while_a_poll_is_reading_it_is_finished_rather_than_gone()
    {
        // A poll asks the target two questions - has the job left an exit status, and is its
        // process still alive - and a job can finish between them. Answered from those two alone
        // that reads as `gone`, which is what a caller is told when a job was signalled or the
        // machine restarted, and it is terminal: the caller stops asking and never collects the
        // output sitting on the target. Seen on CI on 2026-08-28, as
        // A_job_outlives_the_call_that_started_it reading `gone` where it had waited for finished.
        //
        // The window is opened deliberately rather than raced for. The pid file is replaced by a
        // fifo, so the `cat` that reads it blocks until this test writes to the other end - and
        // that open is itself the signal that the first question has already been asked and
        // answered no. Waiting on the work rather than on a clock, where the work is the target's.
        //
        // The control is A_job_is_killed_as_a_whole_process_group above: a job that really did end
        // without a status still reads `gone`, so this is not a fix that answers finished always.
        var started = await Call("start_job", new { host = "local-test", cmd = "sleep 60" });
        var jobId = started.GetProperty("job_id").GetString()!;

        // The target is this machine over a loopback ssh, so the account's home is this process's.
        var directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), _remoteJobs, jobId);

        var pidPath = Path.Combine(directory, JobCommands.PidFile);
        var exitPath = Path.Combine(directory, JobCommands.ExitFile);

        // The job's own pid, kept and handed back below: `kill -0` on it answers no because that
        // process really is gone, rather than because the number was invented.
        var pid = (await File.ReadAllTextAsync(pidPath)).Trim();

        // Killed first, so nothing of the job's is still writing into the directory while this test
        // stages it. Signalled as a group, the wrapper dies with it and never reaches its
        // `echo $? > exit`, which is what leaves the first question to answer no.
        _ = await Call("kill_job", new { jobId });

        File.Delete(pidPath);
        MakeFifo(pidPath);

        Assert.False(
            File.Exists(exitPath),
            "The job left an exit status behind, so the poll answers on its first question and this "
                + "test would prove nothing.");

        var polling = Call("poll_job", new { jobId, sinceLine = 0 });

        // Blocks until the target's `cat` opens the far end. The timeout is a hang guard rather
        // than an assertion about how long anything takes: if that open never happens there is
        // nothing to wake this thread, and a test that fails is better than a suite that stops.
        var opened = await Task.Run(
                () => new FileStream(pidPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
            .WaitAsync(TimeSpan.FromSeconds(30));

        await using (opened)
        {
            // The job finishes here, inside the window: its exit status is on disk, and the process
            // that wrote it was already gone before the liveness question could be answered.
            await File.WriteAllTextAsync(exitPath, "0\n");

            await opened.WriteAsync(Encoding.UTF8.GetBytes(pid + "\n"));
        }

        var polled = await polling;

        Assert.Equal(JobStatuses.Finished, polled.GetProperty("status").GetString());
        Assert.Equal(0, polled.GetProperty("exit_code").GetInt32());
    }

    [Fact]
    public async Task A_secret_a_job_printed_is_masked_on_the_way_back()
    {
        // The only point at which a job's output can be masked at all. On the target it is a plain
        // file and nothing of SshWarden's is over there to intercept a write - which is why the
        // file is created private, and why this is said out loud rather than implied.
        var started = await Call("start_job", new
        {
            host = "local-test",
            cmd = "echo AKIAIOSFODNN7EXAMPLE",
        });

        var jobId = started.GetProperty("job_id").GetString()!;

        JsonElement polled;
        do
        {
            polled = await Call("poll_job", new { jobId, sinceLine = 0 });
        }
        while (polled.GetProperty("status").GetString() == JobStatuses.Running);

        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", polled.GetProperty("output").GetString()!, StringComparison.Ordinal);
        Assert.Equal(1, polled.GetProperty("redacted_values").GetInt32());
    }

    [Fact]
    public async Task A_job_directory_is_not_readable_by_anybody_else()
    {
        var started = await Call("start_job", new { host = "local-test", cmd = "echo hi" });
        var jobId = started.GetProperty("job_id").GetString()!;

        var listed = await Run(new
        {
            host = "local-test",
            cmd = $"ls -ld ~/.sshwarden/jobs/{jobId}",
        });

        // 0700, set when the directory is made rather than after, so there is no moment where it is
        // not. Everything below it inherits the umask set in the same command.
        Assert.StartsWith("drwx------", listed.GetProperty("stdout").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_job_belonging_to_another_subject_is_not_reachable()
    {
        // The IDOR gate, end to end. The second token is a different subject with the same reach,
        // so nothing but ownership stands between it and the first one's job.
        var started = await Call("start_job", new { host = "local-test", cmd = "sleep 30" });
        var jobId = started.GetProperty("job_id").GetString()!;

        var refusal = await CallAs(OtherToken, "poll_job", new { jobId });

        Assert.Contains("no such job", refusal, StringComparison.Ordinal);

        // And the record keeps the real reason, because the operator reading it is not the one
        // being refused.
        Assert.Contains(
            Records(),
            record => record.TryGetProperty("denied_by", out var why)
                && why.GetString() == "job_not_owned");
    }

    [Fact]
    public async Task The_metrics_endpoint_needs_a_credential_like_everything_else()
    {
        // The `host` label carries the names of this deployment's production machines, which is the
        // same information the scope design goes out of its way never to publish. So it is
        // authenticated, and it is not marked otherwise where it is mapped - a scraper is given a
        // token like any other caller.
        using var anonymous = new HttpRequestMessage(HttpMethod.Get, new Uri("/metrics", UriKind.Relative));
        using var refused = await _client.SendAsync(anonymous, CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);

        // The control: with a credential it answers, and it answers in the format a scraper reads.
        var text = await Scrape();

        Assert.Contains("# TYPE sshwarden_commands_total counter", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_numbers_and_the_log_cannot_disagree()
    {
        // The reason the measurement is taken off the audit record rather than inside each tool:
        // one stream, so "the dashboard says forty and the log has thirty-nine lines" cannot happen.
        var before = Records().Count;

        _ = await Run(new { host = "local-test", cmd = "echo one" });
        _ = await CallExpectingRefusal("run", new { host = "prod-web-1", cmd = "echo two" });

        var written = Records().Count - before;
        var text = await Scrape();

        var counted = SeriesTotal(text, "sshwarden_commands_total");

        Assert.Equal(Records().Count, counted);
        Assert.Equal(2, written);
    }

    [Fact]
    public async Task A_refusal_is_counted_by_the_rule_that_refused()
    {
        _ = await CallExpectingRefusal("run", new { host = "prod-web-1", cmd = "echo one" });

        var text = await Scrape();

        Assert.Contains(
            "sshwarden_denied_total{rule=\"host_not_granted\",tool=\"run\"}",
            text,
            StringComparison.Ordinal);

        // And the host the caller named is not on a series of its own, because it is not a host this
        // deployment declared - it is a string somebody sent.
        Assert.Contains("host=\"unknown\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_command_that_exits_non_zero_is_a_failure_rather_than_a_refusal()
    {
        // The distinction an operator alerts on. A command that ran and returned 3 is the host
        // saying no; a refusal is this server saying no; and they want different people woken up.
        _ = await Run(new { host = "local-test", cmd = "exit 3" });

        var text = await Scrape();

        Assert.Contains(
            "sshwarden_commands_total{host=\"local-test\",outcome=\"fail\"} 1",
            text,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Output_is_measured_before_the_cut_rather_than_after()
    {
        // The instrument exists to answer whether the byte cap is the right size, and measuring
        // after the cut would report the cap back to itself: every observation would land in the
        // bucket the cap put it in, and the question would be unanswerable from its own data.
        _ = await Run(new { host = "local-test", cmd = "head -c 200000 /dev/zero | tr '\\0' 'x'" });

        var text = await Scrape();

        // Above the 65536 boundary, which is only visible because the measurement happened first.
        var atCap = SeriesValue(text, "sshwarden_output_bytes_bucket{le=\"65536\"}");
        var total = SeriesValue(text, "sshwarden_output_bytes_bucket{le=\"+Inf\"}");

        Assert.True(total > atCap, $"an observation above the cap should exist: {atCap} of {total} at or below it");
    }

    private async Task<string> Scrape()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/metrics", UriKind.Relative));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await _client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(CancellationToken.None);
    }

    /// <summary>Adds up every series of one counter.</summary>
    private static long SeriesTotal(string text, string metric)
        => text.Split('\n')
            .Where(line => line.StartsWith(metric + "{", StringComparison.Ordinal))
            .Sum(line => long.Parse(line[(line.LastIndexOf(' ') + 1)..], CultureInfo.InvariantCulture));

    /// <summary>Reads one sample by its exact name and labels.</summary>
    private static long SeriesValue(string text, string sample)
        => text.Split('\n')
            .Where(line => line.StartsWith(sample + " ", StringComparison.Ordinal))
            .Select(line => long.Parse(line[(line.LastIndexOf(' ') + 1)..], CultureInfo.InvariantCulture))
            .Single();

    private Task<JsonElement> Run(object arguments) => Call("run", arguments);

    private async Task<string> CallAs(string token, string tool, object arguments)
    {
        using var response = await Send(tool, arguments, token);
        var result = await ReadResultAsync(response);

        Assert.True(
            result.TryGetProperty("isError", out var isError) && isError.GetBoolean(),
            "The call was not refused: " + result.GetRawText());

        return result.GetProperty("content")[0].GetProperty("text").GetString()!;
    }

    private async Task<string> CallExpectingRefusal(string tool, object arguments)
    {
        using var response = await Send(tool, arguments);
        var result = await ReadResultAsync(response);

        Assert.True(
            result.TryGetProperty("isError", out var isError) && isError.GetBoolean(),
            "The call was not refused: " + result.GetRawText());

        // The decoded message rather than the JSON around it, so an assertion about the words the
        // caller reads is not quietly satisfied - or defeated - by escaping.
        return result.GetProperty("content")[0].GetProperty("text").GetString()!;
    }

    /// <summary>Creates a fifo, which the framework has no API for.</summary>
    /// <remarks>
    /// Fails rather than skips when there is nothing to create one with, for the same reason the
    /// fixture fails without an sshd: a test that skips itself is green in exactly the situation
    /// where it measured nothing.
    /// </remarks>
    private static void MakeFifo(string path)
    {
        using var process = Process.Start(new ProcessStartInfo("mkfifo")
        {
            ArgumentList = { path },
            RedirectStandardError = true,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException("mkfifo did not start.");

        process.WaitForExit();

        Assert.True(
            process.ExitCode == 0,
            $"mkfifo {path} failed: " + process.StandardError.ReadToEnd());
    }

    private async Task<JsonElement> Call(string tool, object arguments)
    {
        using var response = await Send(tool, arguments);
        var result = await ReadResultAsync(response);

        Assert.False(
            result.TryGetProperty("isError", out var isError) && isError.GetBoolean(),
            "The call was refused: " + result.GetRawText());

        // The tool's own object, which the SDK returns as JSON text in the content block.
        var text = result.GetProperty("content")[0].GetProperty("text").GetString()!;
        using var inner = JsonDocument.Parse(text);
        return inner.RootElement.Clone();
    }

    private async Task<HttpResponseMessage> Send(string tool, object arguments, string? token = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/mcp", UriKind.Relative))
        {
            Content = JsonContent.Create(new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "tools/call",
                @params = new { name = tool, arguments },
            }),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token ?? Token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

        var response = await _client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        return response;
    }

    private static async Task<JsonElement> ReadResultAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(CancellationToken.None);
        var data = body.Split('\n').First(line => line.StartsWith("data: ", StringComparison.Ordinal));

        using var document = JsonDocument.Parse(data["data: ".Length..]);
        return document.RootElement.GetProperty("result").Clone();
    }

    private IReadOnlyList<JsonElement> Records()
        => File.Exists(_auditPath)
            ? [.. File.ReadAllLines(_auditPath).Where(line => line.Length > 0)
                .Select(line => JsonDocument.Parse(line).RootElement.Clone())]
            : [];
}
