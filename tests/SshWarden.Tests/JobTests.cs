using System.Text.Json;

using SshWarden.Auth;
using SshWarden.Authorization;
using SshWarden.Jobs;

using Xunit;

namespace SshWarden.Tests;

public sealed class JobStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), "sshwarden-jobs", Guid.NewGuid().ToString("n"));

    public JobStoreTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public void A_job_id_is_not_guessable()
    {
        // The only argument poll_job and kill_job take, so a counter would be a way to reach other
        // people's jobs by trying rather than by being allowed.
        var ids = Enumerable.Range(0, 200).Select(_ => JobStore.NewJobId()).ToList();

        Assert.Equal(ids.Count, ids.Distinct(StringComparer.Ordinal).Count());
        Assert.All(ids, id => Assert.True(id.Length > 20, id));
        Assert.All(ids, id => Assert.StartsWith("sw_job_", id, StringComparison.Ordinal));
    }

    [Fact]
    public void A_job_survives_a_restart_of_this_server()
    {
        // The thing docs/DESIGN.md §4.4 said had to be settled before jobs could ship. The process runs
        // on the target and outlives a restart here; an in-memory registry would leave every
        // running job unpollable, unkillable and unowned - and unowned is the worst of the three,
        // because the check that stops one caller reaching another's job would have nothing to
        // compare against.
        var path = Path.Combine(_directory, "jobs.jsonl");

        using (var store = new JobStore(path))
        {
            store.Put(Job("sw_job_one", "someone"));
        }

        using var reopened = new JobStore(path);

        var job = reopened.Find("sw_job_one");
        Assert.NotNull(job);
        Assert.Equal("someone", job.OwnerSubject);
    }

    [Fact]
    public void The_latest_entry_for_a_job_wins()
    {
        // Mutation is an appended record rather than a rewrite, so a crash partway through a write
        // costs the last line rather than the file.
        var path = Path.Combine(_directory, "jobs.jsonl");

        using (var store = new JobStore(path))
        {
            store.Put(Job("sw_job_one", "someone"));
            store.Put(Job("sw_job_one", "someone", killedAt: DateTimeOffset.UnixEpoch));
        }

        using var reopened = new JobStore(path);

        Assert.NotNull(reopened.Find("sw_job_one")!.KilledAt);
    }

    [Fact]
    public void A_truncated_last_line_costs_that_job_rather_than_the_server()
    {
        var path = Path.Combine(_directory, "jobs.jsonl");

        using (var store = new JobStore(path))
        {
            store.Put(Job("sw_job_one", "someone"));
        }

        File.AppendAllText(path, "{\"job_id\":\"sw_job_tw");

        using var reopened = new JobStore(path);

        // Starting is what matters. Refusing to start over one truncated line would turn a lost job
        // into a lost server.
        Assert.NotNull(reopened.Find("sw_job_one"));
    }

    private static JobRecord Job(string id, string subject, DateTimeOffset? killedAt = null) => new()
    {
        JobId = id,
        Host = "prod-web-1",
        OwnerSubject = subject,
        OwnerGrantId = "a-grant",
        AllowedBy = "a-rule",
        SshUser = "deploy",
        Command = "sleep 100",
        Workdir = "~",
        Directory = ".sshwarden/jobs/" + id,
        StartedAt = DateTimeOffset.UnixEpoch,
        KilledAt = killedAt,
    };
}

public sealed class JobCommandTests
{
    [Fact]
    public void A_job_leads_its_own_process_group_and_session()
    {
        // Leading a group is what makes killing it kill the pipeline rather than its first stage.
        // Leaving the session is what stops it dying when the SSH channel closes.
        var command = JobCommands.Start(".sshwarden/jobs/x", "sleep 100", workdir: null);

        Assert.Contains("setsid sh -c", command, StringComparison.Ordinal);
        Assert.Contains("echo $$ >", command, StringComparison.Ordinal);
    }

    [Fact]
    public void The_job_directory_is_private_from_the_moment_it_exists()
    {
        // Its output is unredacted on the target and cannot be otherwise - the command writes to it
        // directly. The mode is what bounds who can read it, and it is set at creation rather than
        // afterwards so there is no moment where it is not.
        var command = JobCommands.Start(".sshwarden/jobs/x", "true", workdir: null);

        Assert.Contains("umask 077", command, StringComparison.Ordinal);
        Assert.Contains("mkdir -p -m 700 --", command, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_job_path_expands_the_home_and_nothing_else()
    {
        // Two quoting styles in one word, and the split is the whole point: the home is the shell's
        // own variable and has to expand, everything after it came from configuration and must not.
        // This went the other way once - the whole path was single-quoted, so `$HOME` arrived at the
        // target literally, the job directory was created under a directory named `$HOME`, the pid
        // file was never found and `kill_job` reported success having signalled nothing.
        var start = JobCommands.Start(".sshwarden/jobs/x", "true", workdir: null);
        var poll = JobCommands.Poll(".sshwarden/jobs/x", sinceLine: 0);
        var kill = JobCommands.Kill(".sshwarden/jobs/x");

        foreach (var command in new[] { start, poll, kill })
        {
            Assert.Contains("\"$HOME\"/'.sshwarden/jobs/x", command, StringComparison.Ordinal);
            Assert.DoesNotContain("'$HOME", command, StringComparison.Ordinal);
        }
    }

    // Whether the caller's command survives being nested inside the job wrapper is a question about
    // what a real shell does with two levels of quoting, and a string assertion cannot settle it -
    // any literal this file could check would be a copy of the implementation. It is tested against
    // a real shell instead: see the job tests in SshWarden.Ssh.IntegrationTests.

    [Fact]
    public void The_exit_status_is_looked_for_again_once_the_process_is_gone()
    {
        // A poll asks two questions, and a job can finish between them: no exit status yet, then
        // the process ends, then the liveness test finds nothing alive. Answered from those two
        // alone that reads as `gone` - signalled, or the machine restarted - for a job that
        // finished and left its output behind, and `gone` is terminal, so the caller stops asking.
        //
        // This assertion is the weak half of a pair, like the kill one below: a string check cannot
        // know what a shell does with an interleaving.
        // A_job_that_finishes_while_a_poll_is_reading_it_is_finished_rather_than_gone in the
        // integration suite is what settles it, by holding the window open with a fifo. This is
        // here so the reason sits with the command.
        var command = JobCommands.Poll(".sshwarden/jobs/x", sinceLine: 0);

        var exit = $"\"$HOME\"/'.sshwarden/jobs/x/{JobCommands.ExitFile}'";

        Assert.Equal(2, Occurrences(command, $"[ -s {exit} ]"));

        // Empty is not finished. The file exists from the moment the redirection creates it and
        // holds a status a moment later, so `-f` answers finished with no exit code at all for a
        // status that is still being written.
        Assert.DoesNotContain($"[ -f {exit} ]", command, StringComparison.Ordinal);
    }

    [Fact]
    public void Killing_signals_the_group_rather_than_the_leader()
    {
        // Killing only the leader of `a | b | c` leaves the rest running and reports success.
        var command = JobCommands.Kill(".sshwarden/jobs/x");

        Assert.Contains("kill -TERM \"-$p\"", command, StringComparison.Ordinal);
        Assert.Contains("kill -KILL \"-$p\"", command, StringComparison.Ordinal);
    }

    [Fact]
    public void No_option_terminator_before_a_signal_target()
    {
        // `kill -TERM -- "-$p"` reads as the careful spelling and is the broken one: dash's builtin
        // rejects it with `Illegal number: -`, so the signal went nowhere and kill_job reported
        // success while the job kept running. Measured against dash 0.5.12 on 2026-08-26.
        //
        // This assertion is the weak half of a pair on purpose - a string check cannot know what a
        // shell accepts, and the version of it that asserted the `--` form passed for exactly as
        // long as the command was broken. A_job_is_killed_as_a_whole_process_group in the
        // integration suite is what settles it; this is here so the reason sits with the command.
        var command = JobCommands.Kill(".sshwarden/jobs/x");

        Assert.DoesNotContain("kill -TERM --", command, StringComparison.Ordinal);
        Assert.DoesNotContain("kill -KILL --", command, StringComparison.Ordinal);
    }

    [Fact]
    public void Starting_does_not_return_until_the_job_has_a_process_group()
    {
        // Measured on 2026-08-26: without the wait the pid file was absent at the instant the
        // command printed `started` on 300 starts out of 300, so the contract was not racy, it was
        // false every time. This assertion is what goes red for the contract itself; the failure a
        // caller can see is A_job_that_cannot_start_is_refused_rather_than_accepted in the
        // integration suite. The rest of that suite stays green without the wait, because every way
        // of observing a job costs an SSH round trip and the job wins that race.
        var command = JobCommands.Start(".sshwarden/jobs/x", "true", workdir: null);

        Assert.Contains("while [ ! -s \"$HOME\"/'.sshwarden/jobs/x/pid' ]", command, StringComparison.Ordinal);
        Assert.Contains($"exit {JobCommands.NoProcessGroup}", command, StringComparison.Ordinal);
    }

    [Fact]
    public void Each_way_of_failing_to_start_has_its_own_status()
    {
        // A bare non-zero says a job did not start and nothing about which of the three things went
        // wrong, and the operator reading it is not the one being refused.
        var command = JobCommands.Start(".sshwarden/jobs/x", "true", workdir: "/srv/app");

        Assert.Contains($"|| exit {JobCommands.DirectoryFailed}", command, StringComparison.Ordinal);
        Assert.Contains($"|| exit {JobCommands.WorkdirFailed}", command, StringComparison.Ordinal);
        Assert.Contains($"exit {JobCommands.NoProcessGroup}", command, StringComparison.Ordinal);

        Assert.NotEqual(JobCommands.DirectoryFailed, JobCommands.WorkdirFailed);
        Assert.NotEqual(JobCommands.WorkdirFailed, JobCommands.NoProcessGroup);
    }

    [Fact]
    public void A_job_that_never_starts_says_why_rather_than_losing_it()
    {
        // The wrapper's stderr went to /dev/null, so a job that could not start left no trace and
        // the only thing anybody was told was that it had not started. A shell syntax error in the
        // caller's command is exactly that case, and it is the one that happened.
        var command = JobCommands.Start(".sshwarden/jobs/x", "true", workdir: null);

        Assert.Contains(
            $"2> \"$HOME\"/'.sshwarden/jobs/x/{JobCommands.ErrorFile}'",
            command,
            StringComparison.Ordinal);

        Assert.Contains(
            $"cat \"$HOME\"/'.sshwarden/jobs/x/{JobCommands.ErrorFile}' >&2",
            command,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("running \nsome output\n", JobStatuses.Running, null, "some output\n")]
    [InlineData("finished 0\nall done\n", JobStatuses.Finished, 0, "all done\n")]
    [InlineData("finished 3\n", JobStatuses.Finished, 3, "")]
    [InlineData("gone \n", JobStatuses.Gone, null, "")]
    [InlineData("vanished \n", JobStatuses.Vanished, null, "")]
    public void The_status_line_is_read_off_the_front(string output, string status, int? exit, string rest)
    {
        var parsed = JobCommands.ParsePoll(output);

        Assert.Equal(status, parsed.Status);
        Assert.Equal(exit, parsed.ExitCode);
        Assert.Equal(rest, parsed.Output);
    }

    [Fact]
    public void Output_with_no_status_line_is_gone_rather_than_guessed_at()
    {
        // A job reported finished with an invented exit code would say the command completed when
        // nobody knows whether it did.
        var parsed = JobCommands.ParsePoll("something unexpected");

        Assert.Equal(JobStatuses.Gone, parsed.Status);
        Assert.Null(parsed.ExitCode);
    }

    private static int Occurrences(string text, string value)
    {
        var count = 0;

        for (var at = text.IndexOf(value, StringComparison.Ordinal);
             at >= 0;
             at = text.IndexOf(value, at + value.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }
}

public sealed class JobOwnershipGateTests
{
    private static readonly Grant Jobs = new()
    {
        Id = "job-rule",
        Subject = "someone",
        Tools = ["start_job", "poll_job", "kill_job"],
        Hosts = ["prod-web-1"],
        SshUser = "deploy",
    };

    [Fact]
    public void A_caller_reaches_their_own_job()
    {
        // The control.
        var decision = Policy(("sw_job_mine", "prod-web-1", "someone"))
            .AllowsArguments(Caller("someone"), "poll_job", Arguments(("jobId", "sw_job_mine")));

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void A_caller_does_not_reach_somebody_elses_job()
    {
        // The IDOR this gate exists for. Without it one caller polls another's job - reading their
        // production output - and signals their processes, and both bypass every host rule at once
        // because the argument carries no host to check.
        var decision = Policy(("sw_job_theirs", "prod-web-1", "someone-else"))
            .AllowsArguments(Caller("someone"), "poll_job", Arguments(("jobId", "sw_job_theirs")));

        Assert.Equal(AuthorizationRefusal.JobNotOwned, decision.RefusedBy);
    }

    [Fact]
    public void Not_yours_and_no_such_job_read_the_same_to_the_caller()
    {
        // Telling a caller that an identifier exists but is not theirs is telling them it exists,
        // which turns the identifier space into something worth searching. The audit record keeps
        // the distinction, because the operator reading it is not the one being refused.
        var theirs = Policy(("sw_job_theirs", "prod-web-1", "someone-else"))
            .AllowsArguments(Caller("someone"), "poll_job", Arguments(("jobId", "sw_job_theirs")));

        var absent = Policy()
            .AllowsArguments(Caller("someone"), "poll_job", Arguments(("jobId", "sw_job_absent")));

        Assert.NotEqual(theirs.RefusedBy, absent.RefusedBy);
        Assert.Equal(theirs.Detail, absent.Detail);
    }

    [Fact]
    public void Owning_a_job_is_not_permission_to_reach_its_host()
    {
        // A rule that stopped covering that host since the job started stops covering the job too.
        var decision = Policy(("sw_job_mine", "prod-db-9", "someone"))
            .AllowsArguments(Caller("someone"), "poll_job", Arguments(("jobId", "sw_job_mine")));

        Assert.Equal(AuthorizationRefusal.HostNotGranted, decision.RefusedBy);
    }

    [Fact]
    public void A_call_naming_no_job_is_refused_as_a_wiring_problem()
    {
        var decision = Policy().AllowsArguments(Caller("someone"), "poll_job", Arguments(("host", "prod-web-1")));

        Assert.Equal(AuthorizationRefusal.JobArgumentMissing, decision.RefusedBy);
    }

    [Fact]
    public void A_build_that_cannot_resolve_a_job_refuses_rather_than_allows()
    {
        // A gate that cannot see the resource has not gated it, and the only answer that is not a
        // guess is no.
        var decision = new GrantTableToolPolicy(new GrantTable([Jobs]), jobs: null)
            .AllowsArguments(Caller("someone"), "poll_job", Arguments(("jobId", "sw_job_mine")));

        Assert.Equal(AuthorizationRefusal.JobNotFound, decision.RefusedBy);
    }

    private static GrantTableToolPolicy Policy(params (string Id, string Host, string Owner)[] jobs)
        => new(new GrantTable([Jobs]), new StubJobs(jobs));

    private static Dictionary<string, JsonElement> Arguments(params (string Name, string Value)[] values)
        => values.ToDictionary(
            pair => pair.Name,
            pair => JsonSerializer.SerializeToElement(pair.Value),
            StringComparer.Ordinal);

    private static CallerIdentity Caller(string subject) => new()
    {
        Subject = subject,
        ClientId = "a-client",
        GrantId = "a-grant",
        TokenId = "a-token",
        Source = "test",
        ScopeClaim = ScopeClaimState.Absent,
        Scopes = new HashSet<string>(StringComparer.Ordinal),
    };

    private sealed class StubJobs : IJobLookup
    {
        private readonly (string Id, string Host, string Owner)[] _jobs;

        public StubJobs((string Id, string Host, string Owner)[] jobs) => _jobs = jobs;

        public (string Host, string OwnerSubject)? Find(string jobId)
        {
            foreach (var (id, host, owner) in _jobs)
            {
                if (string.Equals(id, jobId, StringComparison.Ordinal))
                {
                    return (host, owner);
                }
            }

            return null;
        }
    }
}
