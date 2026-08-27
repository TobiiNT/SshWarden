using System.Text.Json;

using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

using Xunit;

namespace SshWarden.Mcp.Tests;

/// <summary>
/// The startup checks that stop a gate from being wired to nothing.
/// </summary>
/// <remarks>
/// Every failure here is silent without the check: the policy is happy, the unit tests pass, and
/// the boundary is simply not there. That is the whole reason they run at startup rather than being
/// left to the call that would have been refused.
/// </remarks>
public sealed class ToolPolicyCoverageTests
{
    [Fact]
    public void The_tools_this_build_ships_pass()
    {
        // The control. Without it, a check that rejected every arrangement would look like a
        // working one.
        ToolPolicyCoverage.Verify(Shipping());
    }

    [Fact]
    public void A_tool_the_build_implements_but_does_not_register_is_refused()
    {
        // Measured 2026-08-26, and the reason this check exists: one SDK registration overload
        // compiles, runs and registers nothing, leaving a server whose tool list is empty and whose
        // every call answers that the method is not available. Nothing else notices - a gate is
        // perfectly happy covering an empty set.
        var failure = Assert.Throws<InvalidOperationException>(() => ToolPolicyCoverage.Verify([]));

        Assert.Contains("is not registered", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_surface_is_fine_when_no_ssh_layer_is_configured()
    {
        // A deployment part way through setup has no tools and should not have any. The check is
        // about a tool that went missing, not about a deployment that has not configured one yet.
        ToolPolicyCoverage.Verify([], expectTools: false);
    }

    [Fact]
    public void A_tool_taking_a_host_that_the_policy_does_not_gate_is_refused()
    {
        // The dangerous direction: a tool that reaches a machine and whose host nothing checks.
        // Any caller allowed the tool would reach every host, and no test of the policy would fail.
        // `poll_job` is the example because its host is meant to come from the job it resolves -
        // a `host` argument beside that is one the caller chooses and nothing checks.
        var failure = Assert.Throws<InvalidOperationException>(
            () => ToolPolicyCoverage.Verify(Replacing(Tool("poll_job", "host", "jobId"))));

        Assert.Contains("does not gate it on one", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_tool_missing_the_argument_the_policy_gates_on_is_refused()
    {
        // The other direction: the gate looks for an argument the tool does not declare, finds
        // nothing, and cannot tell that from a caller who did not send it.
        var failure = Assert.Throws<InvalidOperationException>(
            () => ToolPolicyCoverage.Verify(Replacing(Tool("run", "machine", "cmd"))));

        Assert.Contains("is not in that tool's input schema", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_tool_taking_a_path_that_the_policy_does_not_gate_is_refused()
    {
        // The selector where getting this wrong is worst: an ungated path reaches every file the
        // unix account can open, which is the whole set the grant table was written to narrow.
        var failure = Assert.Throws<InvalidOperationException>(
            () => ToolPolicyCoverage.Verify(Replacing(Tool("run", "host", "cmd", "path"))));

        Assert.Contains("every file the unix account can open", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_path_gated_tool_missing_the_argument_the_policy_reads_is_refused()
    {
        var failure = Assert.Throws<InvalidOperationException>(
            () => ToolPolicyCoverage.Verify(Replacing(Tool("read_file", "host", "file"))));

        Assert.Contains("is not in that tool's input schema", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_tool_taking_a_job_that_the_policy_does_not_resolve_is_refused()
    {
        // The argument shape where getting this wrong is least visible: a job id names no host, so
        // a gate that only knows how to check hosts sees nothing to check - and what goes through
        // is one caller reading another's production output and signalling their processes.
        var failure = Assert.Throws<InvalidOperationException>(
            () => ToolPolicyCoverage.Verify(Replacing(Tool("run", "host", "cmd", "jobId"))));

        Assert.Contains("including other people's", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_job_gated_tool_missing_the_argument_the_policy_reads_is_refused()
    {
        var failure = Assert.Throws<InvalidOperationException>(
            () => ToolPolicyCoverage.Verify(Replacing(Tool("poll_job", "job"))));

        Assert.Contains("is not in that tool's input schema", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_tool_outside_the_v0_vocabulary_is_refused()
    {
        var failure = Assert.Throws<InvalidOperationException>(
            () => ToolPolicyCoverage.Verify([.. Shipping(), Tool("sudo_everything", "host")]));

        Assert.Contains("not one of the names a grant rule can name", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>The surface as this build actually ships it.</summary>
    private static List<StubTool> Shipping() =>
    [
        Tool("run", "host", "cmd"),
        Tool("read_file", "host", "path"),
        Tool("tail_log", "host", "unitOrPath"),
        Tool("list_changes", "host"),
        Tool("start_job", "host", "cmd"),
        Tool("poll_job", "jobId"),
        Tool("kill_job", "jobId"),
    ];

    /// <summary>The shipping surface with one tool swapped for a broken version of itself.</summary>
    /// <remarks>
    /// Built from the real set rather than from a handful of tools, so a test about one defect does
    /// not accidentally pass because some other tool was missing and tripped a different check
    /// first.
    /// </remarks>
    private static List<StubTool> Replacing(StubTool broken)
        => [.. Shipping().Where(tool => tool.ProtocolTool.Name != broken.ProtocolTool.Name), broken];

    private static StubTool Tool(string name, params string[] properties)
    {
        var schema = JsonSerializer.SerializeToElement(new
        {
            type = "object",
            properties = properties.ToDictionary(
                property => property,
                _ => new { type = "string" }),
        });

        return new StubTool(new Tool { Name = name, InputSchema = schema });
    }

    private sealed class StubTool : McpServerTool
    {
        public StubTool(Tool protocolTool) => ProtocolTool = protocolTool;

        public override Tool ProtocolTool { get; }

        public override IReadOnlyList<object> Metadata => [];

        public override ValueTask<CallToolResult> InvokeAsync(
            RequestContext<CallToolRequestParams> request,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException(
                "This stands in for a registered tool so the startup check has something to look "
                    + "at. It is never called.");
    }
}
