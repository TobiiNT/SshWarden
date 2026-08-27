using Microsoft.Extensions.Logging;

using SshWarden.Changes;
using SshWarden.Diagnostics;
using SshWarden.Jobs;

using Xunit;

namespace SshWarden.Tests;

/// <summary>
/// The two things that used to fail in silence.
/// </summary>
/// <remarks>
/// Both were caught, both were handled correctly, and neither was said out loud. A change detector
/// that has been broken for a week and a job that was dropped on restart look, from outside the
/// process, exactly like a quiet week and a finished job.
/// </remarks>
public sealed class OperationalLoggingTests
{
    [Fact]
    public void A_sweep_problem_is_announced_once_rather_than_every_round()
    {
        // Once, because the sweeper runs on a timer: a host unreachable since Tuesday would
        // otherwise write one identical warning per interval until nobody reads them, which is the
        // same as not logging it at all.
        var log = new CapturedLog();
        var problems = new SweepProblems(log.For<SweepProblems>());

        problems.Set("web-1.example.com", "deploy", "The sweep command exited 2.");
        problems.Set("web-1.example.com", "deploy", "The sweep command exited 2.");
        problems.Set("web-1.example.com", "deploy", "The sweep command exited 2.");

        var warning = Assert.Single(log.Lines, line => line.Level == LogLevel.Warning);

        Assert.Equal(LogEvents.Core + 1, warning.Event.Id);
        Assert.Equal("SweepProblem", warning.Event.Name);
        Assert.Contains("web-1.example.com", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_different_problem_on_the_same_host_is_announced_again()
    {
        // The control for the rule above, and the case it must not swallow: the first problem was a
        // missing -printf and the second is an entry ceiling, which is a different thing to fix.
        var log = new CapturedLog();
        var problems = new SweepProblems(log.For<SweepProblems>());

        problems.Set("web-1.example.com", "deploy", "The sweep command exited 2.");
        problems.Set("web-1.example.com", "deploy", "The sweep hit its ceiling.");

        Assert.Equal(2, log.Lines.Count(line => line.Level == LogLevel.Warning));
    }

    [Fact]
    public void A_recovery_is_announced_and_an_ordinary_sweep_is_not()
    {
        // Clear runs after every successful sweep. Announcing unconditionally would bury the
        // warning under one line per host per interval, so only the transition is news.
        var log = new CapturedLog();
        var problems = new SweepProblems(log.For<SweepProblems>());

        problems.Clear("web-1.example.com", "deploy");
        Assert.Empty(log.Lines);

        problems.Set("web-1.example.com", "deploy", "The sweep command exited 2.");
        problems.Clear("web-1.example.com", "deploy");

        var recovery = Assert.Single(log.Lines, line => line.Level == LogLevel.Information);

        Assert.Equal(LogEvents.Core + 2, recovery.Event.Id);
        Assert.Equal("SweepRecovered", recovery.Event.Name);
    }

    [Fact]
    public void A_registry_line_that_will_not_replay_is_announced_with_its_number()
    {
        // Skipping it is right - the likely cause is a crash partway through the last write, and
        // refusing to start over one truncated line turns a lost job into a lost server. Saying
        // nothing is not: poll_job will answer "no such job" for work still running on the target.
        var directory = Path.Combine(Path.GetTempPath(), "sshwarden-log", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        var path = Path.Combine(directory, "jobs.jsonl");

        // Written by the store itself rather than by hand, so the readable lines are readable for
        // the same reason a real registry's are - and a change to the record's shape does not turn
        // this into a test where every line is the corrupt one.
        using (var writer = new JobStore(path))
        {
            writer.Put(Record("sw_job_1"));
            writer.Put(Record("sw_job_2"));
        }

        // A crash partway through a write, which is the case this is about.
        File.AppendAllText(path, "{\"job_id\":\"sw_job_3\",\"host\":\"web-1.exa");

        var log = new CapturedLog();

        using (var store = new JobStore(path, log.For<JobStore>()))
        {
            // The readable lines still replayed: skipping the bad one must not cost the others.
            Assert.NotNull(store.Find("sw_job_1"));
            Assert.NotNull(store.Find("sw_job_2"));
            Assert.Null(store.Find("sw_job_3"));
        }

        var skipped = Assert.Single(log.Lines, line => line.Level == LogLevel.Warning);

        Assert.Equal(LogEvents.Core + 3, skipped.Event.Id);
        Assert.Equal("JobRegistryLineSkipped", skipped.Event.Name);

        // The line number, so an operator can go and look at it. Not its contents: a job record
        // carries a command, and a command carries whatever the caller put in it.
        Assert.Contains("3", skipped.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("web-1.exa", skipped.Message, StringComparison.Ordinal);
    }

    private static JobRecord Record(string jobId) => new()
    {
        JobId = jobId,
        Host = "web-1.example.com",
        OwnerSubject = "someone",
        OwnerGrantId = "bw_grant_1",
        AllowedBy = "someone-web",
        SshUser = "deploy",
        Command = "echo hello",
        Workdir = "~",
        Directory = ".sshwarden/jobs/" + jobId,
        StartedAt = DateTimeOffset.UnixEpoch,
    };
}
