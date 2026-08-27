using System.Text;

using SshWarden.Output;

using Xunit;

namespace SshWarden.Tests;

public sealed class OutputBudgetTests
{
    [Fact]
    public void Output_within_the_budget_is_returned_whole()
    {
        // The control. Without it, a budget that truncated everything would look like a working one.
        var result = OutputBudget.Apply("small\noutput\n", 4096);

        Assert.Equal("small\noutput\n", result.Text);
        Assert.False(result.Truncated);
        Assert.Equal(0, result.DroppedLines);
    }

    [Fact]
    public void Output_over_the_budget_keeps_the_head_and_the_tail()
    {
        var text = string.Join('\n', Enumerable.Range(0, 5000).Select(index => $"line {index}"));

        var result = OutputBudget.Apply(text, 2048);

        Assert.True(result.Truncated);

        // The head says what the command was doing; the tail says how it ended, which is where the
        // error usually is. Keeping only one end loses one of those.
        Assert.Contains("line 0", result.Text, StringComparison.Ordinal);
        Assert.Contains("line 4999", result.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("line 2500", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_tail_gets_more_room_than_the_head()
    {
        var text = string.Join('\n', Enumerable.Range(0, 5000).Select(index => $"line {index}"));

        var result = OutputBudget.Apply(text, 2048);

        var head = result.Text[..result.Text.IndexOf("[...", StringComparison.Ordinal)];
        var tail = result.Text[(result.Text.IndexOf("...]", StringComparison.Ordinal) + 4)..];

        // Two thirds to the end, because a command that failed says why on its last lines far more
        // often than on its first.
        Assert.True(tail.Length > head.Length, $"head {head.Length}, tail {tail.Length}");
    }

    [Fact]
    public void The_cut_says_what_it_dropped()
    {
        // Without this the caller draws a conclusion from a fragment that reads as complete. It is
        // the whole difference between truncating and lying.
        var text = string.Join('\n', Enumerable.Range(0, 5000).Select(index => $"line {index}"));

        var result = OutputBudget.Apply(text, 2048);

        Assert.Contains("SshWarden truncated", result.Text, StringComparison.Ordinal);
        Assert.Contains(result.DroppedLines.ToString(System.Globalization.CultureInfo.InvariantCulture), result.Text, StringComparison.Ordinal);
        Assert.Contains("bytes", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_result_fits_roughly_in_the_budget()
    {
        var text = string.Join('\n', Enumerable.Range(0, 20000).Select(index => $"line {index}"));

        var result = OutputBudget.Apply(text, 4096);

        // The marker is allowed on top of the budget - it is the thing that says the budget was
        // reached, so charging it against the budget would shrink the answer to pay for the
        // explanation.
        Assert.True(
            Encoding.UTF8.GetByteCount(result.Text) < 4096 + 200,
            $"kept {Encoding.UTF8.GetByteCount(result.Text)} bytes");
    }

    [Fact]
    public void One_line_longer_than_the_budget_is_still_cut()
    {
        // `cat` of something with no newlines in it. Whole-line trimming cannot help, so the
        // fallback has to - otherwise the budget silently does not apply to the exact input most
        // likely to blow past it.
        var text = new string('x', 100_000);

        var result = OutputBudget.Apply(text, 2048);

        Assert.True(result.Truncated);
        Assert.True(Encoding.UTF8.GetByteCount(result.Text) < 2048 + 200);
        Assert.Contains("SshWarden truncated", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_cut_never_splits_a_character()
    {
        // Every character here is a surrogate pair, so a cut that counted UTF-16 units would land
        // between the halves of one and produce something that is not text in any encoding.
        var text = string.Concat(Enumerable.Repeat("\U0001F600", 20_000));

        var result = OutputBudget.Apply(text, 2048);

        Assert.True(result.Truncated);
        Assert.DoesNotContain(result.Text, character => char.IsSurrogate(character)
            && !IsPartOfAPair(result.Text, character));

        static bool IsPartOfAPair(string text, char _) =>
            !text.Where((character, index) => char.IsHighSurrogate(character)
                && (index + 1 >= text.Length || !char.IsLowSurrogate(text[index + 1]))).Any();
    }
}

public sealed class OutputFilterTests
{
    [Fact]
    public void Only_matching_lines_survive()
    {
        var result = OutputFilter.Apply("alpha\nbeta\ngamma\n", "a$");

        Assert.True(result.Applied);
        Assert.Equal("alpha\nbeta\ngamma", result.Text);
    }

    [Fact]
    public void A_pattern_matching_nothing_returns_nothing()
    {
        var result = OutputFilter.Apply("alpha\nbeta\n", "zeta");

        Assert.True(result.Applied);
        Assert.Equal(string.Empty, result.Text);
    }

    [Fact]
    public void An_unusable_pattern_says_so_rather_than_filtering_nothing()
    {
        // The dangerous alternative is returning the unfiltered output silently: the caller asked
        // for a subset, gets everything, and reads the extra lines as matches.
        var result = OutputFilter.Apply("alpha\nbeta\n", "(unclosed");

        Assert.False(result.Applied);
        Assert.NotNull(result.Problem);
        Assert.Equal("alpha\nbeta\n", result.Text);
    }

    [Fact]
    public void A_lookaround_is_refused_rather_than_run_on_a_backtracking_engine()
    {
        // The trade this project chose, stated as a test rather than as a comment. The pattern is
        // supplied by an agent, and the engine that cannot be made to blow up is the one without
        // lookarounds - so falling back to the engine that has them would hand an agent a denial of
        // service against the choke point.
        var result = OutputFilter.Apply("alpha\n", "(?=a)alpha");

        Assert.False(result.Applied);
        Assert.Contains("non-backtracking", result.Problem!, StringComparison.Ordinal);
    }

    [Fact]
    public void A_pattern_built_to_backtrack_still_answers()
    {
        // The classic catastrophic shape. Asserting that it answers rather than how fast: a timing
        // assertion is a flake, and what matters is that it terminates.
        var result = OutputFilter.Apply(new string('a', 2000) + "b\nkeep\n", "(a+)+$");

        Assert.True(result.Applied);
        Assert.Equal(string.Empty, result.Text);
    }
}

public sealed class OutputPipelineTests
{
    [Fact]
    public void The_measurement_is_of_what_the_host_produced()
    {
        // Not of what the caller receives. An agent comparing the two can tell how much it is not
        // seeing; a number taken after filtering would only describe SshWarden's own processing.
        var text = string.Join('\n', Enumerable.Range(0, 5000).Select(index => $"line {index}"));

        var prepared = OutputPipeline.Prepare(text, grep: "line 1$", maxBytes: 2048);

        Assert.Equal(Encoding.UTF8.GetByteCount(text), prepared.RawBytes);
    }

    [Fact]
    public void A_private_key_split_by_the_budget_is_masked_before_it_is_split()
    {
        // **The reason the order is fixed, in its most realistic form.** A private key is many
        // lines, and the budget keeps whole lines from the head - so cutting first leaves the
        // opening lines of the key in the answer, and those lines are base64 that matches no
        // pattern on its own. The block rule only ever sees a key that is still whole, which is
        // true exactly once: before the cut.
        var key = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + string.Join('\n', Enumerable.Repeat("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz", 40))
            + "\n-----END OPENSSH PRIVATE KEY-----";

        var text = key + "\n" + string.Join('\n', Enumerable.Range(0, 400).Select(index => $"line {index}"));

        var prepared = OutputPipeline.Prepare(text, grep: null, maxBytes: 1024);

        Assert.True(prepared.Truncated);
        Assert.DoesNotContain("b3BlbnNzaC1rZXktdjEA", prepared.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN OPENSSH", prepared.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_secret_lying_across_the_cut_is_masked_rather_than_leaked_in_pieces()
    {
        // The same rule where the cut lands mid-character-run rather than between lines: one long
        // line with no newlines in it, which is what `cat` of a single-line config produces. The
        // key is positioned so the head boundary falls inside it - cut first and the answer carries
        // a fragment of the key that no pattern matches.
        const string Secret = "AKIAIOSFODNN7EXAMPLE";
        const int MaxBytes = 1024;

        // The head keeps a third of the budget, so the boundary is around here. The filler is
        // punctuation rather than letters on purpose: the patterns are word-boundary anchored, so a
        // key with letters run straight onto it is a key they do not match at all - a limit of
        // masking recorded on SecretRedactor, and not the thing this test is about.
        var headBoundary = MaxBytes / 3;
        var text = new string('.', headBoundary - (Secret.Length / 2))
            + Secret
            + new string('.', 4000);

        var prepared = OutputPipeline.Prepare(text, grep: null, maxBytes: MaxBytes);

        Assert.True(prepared.Truncated);
        Assert.DoesNotContain(Secret, prepared.Text, StringComparison.Ordinal);

        // And no fragment of it either. This is the assertion that fails when the cut runs first:
        // the head would end partway through the key and carry the first half out.
        Assert.DoesNotContain("AKIAIOSFOD", prepared.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Filtering_happens_before_masking_so_a_pattern_matches_what_the_host_printed()
    {
        // The caller greps what the host actually wrote, and the matching line comes back masked.
        // Grepping masked text instead would report no matches for content that is there.
        var text = "unrelated\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\nalso unrelated\n";

        var prepared = OutputPipeline.Prepare(text, grep: "wJalrXUtnFEMI", maxBytes: 4096);

        Assert.Contains("AWS_SECRET_ACCESS_KEY", prepared.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("wJalrXUtnFEMI", prepared.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("unrelated", prepared.Text, StringComparison.Ordinal);
        Assert.Equal(1, prepared.RedactedCount);
    }

    [Fact]
    public void Ordinary_output_passes_through_untouched()
    {
        // Control for the whole pipeline.
        var prepared = OutputPipeline.Prepare("hello\nworld\n", grep: null, maxBytes: 4096);

        Assert.Equal("hello\nworld\n", prepared.Text);
        Assert.False(prepared.Truncated);
        Assert.Equal(0, prepared.RedactedCount);
        Assert.Null(prepared.FilterProblem);
    }
}
