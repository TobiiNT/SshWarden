using SshWarden.Changes;

using Xunit;

namespace SshWarden.Tests;

public sealed class SweepCommandTests
{
    [Fact]
    public void The_sweep_reads_inode_size_and_modification_time()
    {
        var states = SweepCommand.Parse("12\t34\t1700000000.5\t/etc/hosts\0");

        var state = Assert.Single(states);
        Assert.Equal("/etc/hosts", state.Key);
        Assert.Equal(new FileState(12, 34, 1700000000.5), state.Value);
    }

    [Fact]
    public void A_path_containing_a_newline_stays_one_record()
    {
        // Records are NUL-separated for exactly this. A line-oriented format would split one file
        // into two records, and the second would parse as garbage or - worse - as a real file.
        var states = SweepCommand.Parse("1\t2\t3\t/etc/od\nd\0");

        Assert.Equal("/etc/od\nd", Assert.Single(states).Key);
    }

    [Fact]
    public void A_path_containing_a_tab_stays_intact()
    {
        // The path is last and the split takes only the first three tabs.
        var states = SweepCommand.Parse("1\t2\t3\t/etc/a\tb\0");

        Assert.Equal("/etc/a\tb", Assert.Single(states).Key);
    }

    [Fact]
    public void A_malformed_record_costs_only_its_own_entry()
    {
        // One filename doing something unexpected should not lose every other file's entry.
        var states = SweepCommand.Parse("nonsense\0" + "1\t2\t3\t/etc/hosts\0" + "also\tbad\0");

        Assert.Equal("/etc/hosts", Assert.Single(states).Key);
    }

    [Fact]
    public void A_new_file_is_created_and_a_gone_one_is_deleted()
    {
        var at = DateTimeOffset.UnixEpoch;

        var changes = SweepCommand.Diff(
            new Dictionary<string, FileState> { ["/a"] = new(1, 1, 1) },
            new Dictionary<string, FileState> { ["/b"] = new(2, 2, 2) },
            at);

        Assert.Equal(
            [("/a", FileChangeKinds.Deleted), ("/b", FileChangeKinds.Created)],
            changes.Select(change => (change.Path, change.Kind)));
    }

    [Theory]
    [InlineData(1, 1, 2)]
    [InlineData(1, 2, 1)]
    [InlineData(2, 1, 1)]
    public void A_difference_in_any_of_the_three_is_a_modification(long inode, long size, double modified)
    {
        // Inode as well as size and time, because a file replaced rather than edited keeps its size
        // and can keep its timestamp - `mv new old` is what a config management tool does.
        var changes = SweepCommand.Diff(
            new Dictionary<string, FileState> { ["/a"] = new(1, 1, 1) },
            new Dictionary<string, FileState> { ["/a"] = new(inode, size, modified) },
            DateTimeOffset.UnixEpoch);

        Assert.Equal(FileChangeKinds.Modified, Assert.Single(changes).Kind);
    }

    [Fact]
    public void An_unchanged_file_produces_nothing()
    {
        // The control. Without it, a differ that reported everything every sweep would look like a
        // working one - and would fill the timeline with events that did not happen.
        var same = new Dictionary<string, FileState> { ["/a"] = new(1, 1, 1) };

        Assert.Empty(SweepCommand.Diff(same, same, DateTimeOffset.UnixEpoch));
    }

    [Fact]
    public void The_command_bounds_its_own_output_and_stays_on_one_filesystem()
    {
        var command = SweepCommand.Build(["/etc", "/opt/app"], 5000);

        Assert.Contains("-xdev", command, StringComparison.Ordinal);
        Assert.Contains("head -z -n 5000", command, StringComparison.Ordinal);
        Assert.Contains("'/etc'", command, StringComparison.Ordinal);
    }

    [Fact]
    public void A_watched_path_containing_shell_syntax_is_a_path_and_not_a_program()
    {
        var command = SweepCommand.Build(["/tmp/'; id; '"], 100);

        Assert.Contains("'/tmp/'\\''; id; '\\'''", command, StringComparison.Ordinal);
    }
}

public sealed class ChangeTimelineTests
{
    private static readonly DateTimeOffset Noon = new(2026, 8, 26, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_query_returns_what_fell_in_its_window()
    {
        var timeline = new ChangeTimeline(TimeSpan.FromHours(1));

        timeline.RecordSweep("host", Noon.AddMinutes(-30), [Change(Noon.AddMinutes(-30), "/old")]);
        timeline.RecordSweep("host", Noon.AddMinutes(-2), [Change(Noon.AddMinutes(-2), "/recent")]);

        var recent = timeline.Since("host", TimeSpan.FromMinutes(10), Noon);

        Assert.Equal("/recent", Assert.Single(recent).Path);
    }

    [Fact]
    public void A_host_that_was_never_swept_answers_empty()
    {
        // Empty, and the tool that calls this is responsible for saying that empty here means
        // "nothing was looked at" rather than "nothing changed". The timeline itself cannot know
        // the difference and does not pretend to.
        Assert.Empty(new ChangeTimeline(TimeSpan.FromHours(1)).Since("host", TimeSpan.FromMinutes(10), Noon));
    }

    [Fact]
    public void Entries_older_than_the_retention_are_dropped()
    {
        var timeline = new ChangeTimeline(TimeSpan.FromMinutes(10));

        timeline.RecordSweep("host", Noon.AddMinutes(-60), [Change(Noon.AddMinutes(-60), "/ancient")]);
        timeline.RecordSweep("host", Noon, [Change(Noon, "/now")]);

        Assert.Equal("/now", Assert.Single(timeline.Since("host", TimeSpan.FromHours(2), Noon)).Path);
    }

    [Fact]
    public void One_change_seen_through_two_accounts_is_one_entry()
    {
        // A host can be swept through more than one connection - the sweep runs as whichever unix
        // account is already there - and two accounts noticing the same edit is one edit.
        var timeline = new ChangeTimeline(TimeSpan.FromHours(1));

        timeline.RecordSweep("host", Noon.AddSeconds(-2), [Change(Noon.AddSeconds(-2), "/etc/hosts")]);
        timeline.RecordSweep("host", Noon.AddSeconds(-1), [Change(Noon.AddSeconds(-1), "/etc/hosts")]);

        Assert.Single(timeline.Since("host", TimeSpan.FromMinutes(1), Noon));
    }

    [Fact]
    public void Sweeps_are_recorded_even_when_they_find_nothing()
    {
        // The record of *when* the sweeper looked, which is what a command's window is measured
        // against. Without it a quiet host would look like an unswept one.
        var timeline = new ChangeTimeline(TimeSpan.FromHours(1));

        timeline.RecordSweep("host", Noon, []);

        Assert.Equal(Noon, timeline.LastSweep("host"));
        Assert.Equal(Noon, timeline.LastSweepAtOrBefore("host", Noon.AddMinutes(1)));
        Assert.Null(timeline.LastSweepAtOrBefore("host", Noon.AddMinutes(-1)));
    }

    private static FileChange Change(DateTimeOffset at, string path)
        => new() { At = at, Path = path, Kind = FileChangeKinds.Modified };
}

public sealed class CommandOverlapTests
{
    private static readonly DateTimeOffset Noon = new(2026, 8, 26, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_command_that_ran_alone_is_exclusive()
    {
        var overlap = new CommandOverlap(TimeSpan.FromHours(1));
        var id = overlap.Begin("host", Noon);
        overlap.Finish("host", id, Noon.AddSeconds(5));

        Assert.Equal(
            CommandOverlap.Exclusive,
            overlap.Describe("host", id, Noon, Noon.AddSeconds(5), Noon.AddSeconds(5)));
    }

    [Fact]
    public void A_command_that_shared_its_window_says_how_many()
    {
        // The honest answer where exact attribution does not exist. An exclusive record's changes
        // are attribution; an overlapping one's are a list of candidates, and a reader has to be
        // able to tell which they are holding.
        var overlap = new CommandOverlap(TimeSpan.FromHours(1));

        var mine = overlap.Begin("host", Noon);
        var theirs = overlap.Begin("host", Noon.AddSeconds(1));
        overlap.Finish("host", theirs, Noon.AddSeconds(3));
        overlap.Finish("host", mine, Noon.AddSeconds(5));

        Assert.Equal(
            "overlapping:1",
            overlap.Describe("host", mine, Noon, Noon.AddSeconds(5), Noon.AddSeconds(5)));
    }

    [Fact]
    public void A_command_on_another_host_does_not_count()
    {
        var overlap = new CommandOverlap(TimeSpan.FromHours(1));

        var mine = overlap.Begin("host", Noon);
        _ = overlap.Begin("elsewhere", Noon);

        Assert.Equal(
            CommandOverlap.Exclusive,
            overlap.Describe("host", mine, Noon, Noon.AddSeconds(5), Noon.AddSeconds(5)));
    }

    [Fact]
    public void A_command_that_finished_before_the_window_does_not_count()
    {
        var overlap = new CommandOverlap(TimeSpan.FromHours(1));

        var earlier = overlap.Begin("host", Noon.AddMinutes(-5));
        overlap.Finish("host", earlier, Noon.AddMinutes(-4));
        var mine = overlap.Begin("host", Noon);

        Assert.Equal(
            CommandOverlap.Exclusive,
            overlap.Describe("host", mine, Noon, Noon.AddSeconds(5), Noon.AddSeconds(5)));
    }

    [Fact]
    public void A_command_still_running_overlaps_everything_up_to_now()
    {
        var overlap = new CommandOverlap(TimeSpan.FromHours(1));

        _ = overlap.Begin("host", Noon.AddMinutes(-5));
        var mine = overlap.Begin("host", Noon);

        Assert.Equal(
            "overlapping:1",
            overlap.Describe("host", mine, Noon, Noon.AddSeconds(5), Noon.AddSeconds(5)));
    }
}

public sealed class ChangeAttributionTests
{
    private static readonly DateTimeOffset Noon = new(2026, 8, 26, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_command_no_sweep_covered_gets_a_zero_window_and_no_changes()
    {
        // The case the field exists for. Without a window of zero, an empty change list would read
        // as "nothing changed" when it means "nothing was looked at".
        var attribution = new ChangeAttribution(
            new ChangeTimeline(TimeSpan.FromHours(1)),
            new CommandOverlap(TimeSpan.FromHours(1)));

        var id = attribution.Begin("host", Noon);
        var result = attribution.Finish("host", id, Noon, Noon.AddSeconds(2));

        Assert.Equal(0, result.WindowMs);
        Assert.Empty(result.Changes);
    }

    [Fact]
    public void The_window_is_measured_between_sweeps_rather_than_by_the_command()
    {
        var timeline = new ChangeTimeline(TimeSpan.FromHours(1));
        var attribution = new ChangeAttribution(timeline, new CommandOverlap(TimeSpan.FromHours(1)));

        timeline.RecordSweep("host", Noon.AddSeconds(-10), []);

        var id = attribution.Begin("host", Noon);
        timeline.RecordSweep("host", Noon.AddSeconds(20), [
            new FileChange { At = Noon.AddSeconds(20), Path = "/etc/hosts", Kind = FileChangeKinds.Modified },
        ]);

        var result = attribution.Finish("host", id, Noon, Noon.AddSeconds(2));

        // Thirty seconds - from the sweep before the command to the sweep after it - rather than the
        // two seconds the command took. The command is not what was scanned.
        Assert.Equal(30_000, result.WindowMs);
        Assert.Equal("/etc/hosts", Assert.Single(result.Changes).Path);
        Assert.Equal(CommandOverlap.Exclusive, result.Confidence);
    }

    [Fact]
    public void A_change_from_before_the_command_started_is_not_attributed_to_it()
    {
        var timeline = new ChangeTimeline(TimeSpan.FromHours(1));
        var attribution = new ChangeAttribution(timeline, new CommandOverlap(TimeSpan.FromHours(1)));

        timeline.RecordSweep("host", Noon.AddSeconds(-10), [
            new FileChange { At = Noon.AddSeconds(-10), Path = "/before", Kind = FileChangeKinds.Modified },
        ]);

        var id = attribution.Begin("host", Noon);
        timeline.RecordSweep("host", Noon.AddSeconds(20), []);

        Assert.Empty(attribution.Finish("host", id, Noon, Noon.AddSeconds(2)).Changes);
    }
}
