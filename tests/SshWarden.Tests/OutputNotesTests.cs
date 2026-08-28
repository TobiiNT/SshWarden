using SshWarden.Output;

using Xunit;

namespace SshWarden.Tests;

/// <summary>
/// That output which was not fully processed says so.
/// </summary>
/// <remarks>
/// The redaction rule is proved here rather than end to end, because reaching it through a tool
/// means making a regular expression run out of time - which is an assertion about how long
/// something took, and this suite does not make those.
/// </remarks>
public sealed class OutputNotesTests
{
    [Fact]
    public void Output_that_was_filtered_and_masked_cleanly_says_nothing()
    {
        // The control, and it is the one that gives every other case its meaning: a list that
        // carries something whatever happened tells a caller nothing.
        Assert.Empty(OutputNotes.For(Prepared()));
    }

    [Fact]
    public void Masking_that_did_not_finish_is_reported()
    {
        // "Nothing matched" and "the check did not finish" produce identical text and mean opposite
        // things. Collapsing them reports an unfinished check as a clean one, on the output most
        // likely to be a credential.
        var notes = OutputNotes.For(Prepared(redactionIncomplete: true));

        Assert.Equal([OutputNotes.RedactionIncomplete], notes);
    }

    [Fact]
    public void Masking_that_did_not_finish_on_either_stream_is_reported_once()
    {
        // Two identical sentences read as two separate problems, and there is one remedy.
        var notes = OutputNotes.For(
            Prepared(redactionIncomplete: true),
            Prepared(redactionIncomplete: true));

        Assert.Equal([OutputNotes.RedactionIncomplete], notes);
    }

    [Fact]
    public void A_filter_that_did_not_run_is_reported()
    {
        var notes = OutputNotes.For(Prepared(filterProblem: "The grep pattern was not usable: bad."));

        Assert.Equal(["The grep pattern was not usable: bad."], notes);
    }

    [Fact]
    public void The_same_filter_problem_on_both_streams_is_reported_once()
    {
        var notes = OutputNotes.For(
            Prepared(filterProblem: "The grep pattern was not usable: bad."),
            Prepared(filterProblem: "The grep pattern was not usable: bad."));

        Assert.Equal(["The grep pattern was not usable: bad."], notes);
    }

    [Fact]
    public void Both_problems_at_once_are_both_reported()
    {
        // One does not hide the other. A caller whose filter failed still needs to know the text it
        // got back may be unmasked.
        var notes = OutputNotes.For(
            Prepared(filterProblem: "The grep pattern was not usable: bad.", redactionIncomplete: true));

        Assert.Equal(
            ["The grep pattern was not usable: bad.", OutputNotes.RedactionIncomplete],
            notes);
    }

    private static PreparedOutput Prepared(
        string? filterProblem = null,
        bool redactionIncomplete = false)
        => new()
        {
            Text = "output",
            RawBytes = 6,
            Truncated = false,
            RedactedCount = 0,
            FilterApplied = filterProblem is null,
            FilterProblem = filterProblem,
            RedactionIncomplete = redactionIncomplete,
        };
}
