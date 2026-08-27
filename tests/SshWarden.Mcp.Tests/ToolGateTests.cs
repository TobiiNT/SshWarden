using System.Text.Json;

using SshWarden.Audit;
using SshWarden.Authorization;

using Xunit;

namespace SshWarden.Mcp.Tests;

/// <summary>What the grant table does to a tool listing and to a tool call.</summary>
public sealed class ToolGateTests
{
    [Fact]
    public async Task A_caller_granted_a_tool_sees_it()
    {
        // The control for everything below. Without it, a gate that hid every tool would look like
        // a working one.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var tools = await ListTools(pipeline, AuthenticatedPipeline.ValidToken);

        Assert.Contains("run", tools);
    }

    [Fact]
    public async Task A_caller_not_granted_a_tool_does_not_see_it()
    {
        // Hidden, not shown-and-refused. An agent shown a tool it cannot use will call it, read the
        // refusal and try again - so "this token cannot run commands" has to mean the tool is not
        // there.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var tools = await ListTools(pipeline, AuthenticatedPipeline.ReadOnlyToken);

        Assert.DoesNotContain("run", tools);
    }

    [Fact]
    public async Task A_hidden_tool_is_still_refused_when_called_by_name()
    {
        // The reason the listing filter and the call gate are wired from one call. A client that
        // knows a name can call it whether or not the listing mentioned it, so filtering alone
        // produces a surface that only looks authorized.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var result = await CallRun(pipeline, AuthenticatedPipeline.ReadOnlyToken, AuthenticatedPipeline.AllowedHost);

        Assert.True(IsError(result));
        Assert.Contains(AuthorizationRefusal.ToolNotGranted, TextOf(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_call_filter_asks_whether_the_tool_is_visible_at_all()
    {
        // The two questions are separate by contract - one is "may you see this tool", the other is
        // "may you do it with these arguments" - and the call filter has to ask both. It happens
        // that the grant table's argument check re-derives the tool answer, so with the real policy
        // this test would pass even with the first gate deleted. A policy that separates them
        // cleanly is what makes the contract testable, and a future policy that does separate them
        // is exactly what would break if the first gate went away.
        var policy = new SplitPolicy(allowsTool: false, allowsArguments: true);

        await using var pipeline = await AuthenticatedPipeline.StartAsync(policy);

        var result = await CallRun(pipeline, AuthenticatedPipeline.ValidToken, AuthenticatedPipeline.AllowedHost);

        Assert.True(IsError(result));
        Assert.Contains(SplitPolicy.ToolRefusal, TextOf(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_call_filter_asks_about_the_arguments_too()
    {
        // The control for the pair: the same stub with the answers the other way round.
        var policy = new SplitPolicy(allowsTool: true, allowsArguments: false);

        await using var pipeline = await AuthenticatedPipeline.StartAsync(policy);

        var result = await CallRun(pipeline, AuthenticatedPipeline.ValidToken, AuthenticatedPipeline.AllowedHost);

        Assert.True(IsError(result));
        Assert.Contains(SplitPolicy.ArgumentRefusal, TextOf(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_host_outside_the_grant_is_refused()
    {
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var result = await CallRun(pipeline, AuthenticatedPipeline.ValidToken, AuthenticatedPipeline.ForbiddenHost);

        Assert.True(IsError(result));
        Assert.Contains(AuthorizationRefusal.HostNotGranted, TextOf(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_host_inside_the_grant_gets_past_the_gate()
    {
        // The control for the host rule. This deployment's key file does not exist, so the call
        // fails in the SSH layer - and that is the point: it fails *there* rather than at the gate,
        // and no refusal identifier appears anywhere in the answer.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var result = await CallRun(pipeline, AuthenticatedPipeline.ValidToken, AuthenticatedPipeline.AllowedHost);

        var text = TextOf(result);
        Assert.DoesNotContain(AuthorizationRefusal.HostNotGranted, text, StringComparison.Ordinal);
        Assert.DoesNotContain(AuthorizationRefusal.ToolNotGranted, text, StringComparison.Ordinal);
        Assert.DoesNotContain(AuthorizationRefusal.NoGrantForSubject, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refusal_arrives_as_a_tool_result_rather_than_an_http_status()
    {
        // Measured 2026-08-25 and pinned here: by the time a tool filter runs, the transport has
        // already sent the 200, so a per-tool refusal cannot be a 401 or a 403. If a future SDK or
        // protocol revision changes that, this test is where it shows up rather than in an
        // assumption nobody re-checked.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var result = await CallRun(pipeline, AuthenticatedPipeline.ValidToken, AuthenticatedPipeline.ForbiddenHost);

        // A 200 carrying an error result - CallAsync would have thrown on any other status.
        Assert.True(IsError(result));
        Assert.NotEmpty(TextOf(result));
    }

    [Fact]
    public async Task A_refusal_writes_an_audit_record_naming_the_rule()
    {
        // "An agent went for a production host and was stopped" is the most useful line this log
        // carries, and an earlier version of the schema had nowhere to put it.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        _ = await CallRun(pipeline, AuthenticatedPipeline.ValidToken, AuthenticatedPipeline.ForbiddenHost);

        var record = Assert.Single(pipeline.AuditRecords());

        Assert.Equal(AuditRecordTypes.Decision, record.GetProperty("type").GetString());
        Assert.Equal(AuditDecisions.Deny, record.GetProperty("decision").GetString());
        Assert.Equal(AuthorizationRefusal.HostNotGranted, record.GetProperty("denied_by").GetString());
        Assert.Equal("run", record.GetProperty("tool").GetString());
        Assert.Equal(AuthenticatedPipeline.ForbiddenHost, record.GetProperty("host").GetString());
        Assert.Equal(JsonValueKind.Null, record.GetProperty("selector").ValueKind);

        // All five identity values, on a record for something that did not happen. A refusal is
        // still a record, and a record with a hole in it is the failure this log exists to avoid.
        Assert.Equal(AuthenticatedPipeline.Subject, record.GetProperty("sub").GetString());
        Assert.False(string.IsNullOrEmpty(record.GetProperty("client_id").GetString()));
        Assert.False(string.IsNullOrEmpty(record.GetProperty("gid").GetString()));
        Assert.False(string.IsNullOrEmpty(record.GetProperty("jti").GetString()));
    }

    [Fact]
    public async Task An_allowed_call_writes_no_refusal_record()
    {
        // The control for the record above: a log that recorded a denial for every call would look
        // like a working one from the deny test alone.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        _ = await CallRun(pipeline, AuthenticatedPipeline.ValidToken, AuthenticatedPipeline.AllowedHost);

        Assert.DoesNotContain(
            pipeline.AuditRecords(),
            record => record.GetProperty("decision").GetString() == AuditDecisions.Deny);
    }

    [Fact]
    public async Task An_allowed_call_that_fails_in_the_ssh_layer_records_why()
    {
        // The host in this fixture does not resolve, so the call gets past the gate and then fails.
        // Before this the record read `allow` with a null exit code, a null duration and a null
        // error - three absences a reader has to infer a failure from, and which look the same as a
        // record this process managed to write before something killed it.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        _ = await CallRun(pipeline, AuthenticatedPipeline.ValidToken, AuthenticatedPipeline.AllowedHost);

        var record = Assert.Single(pipeline.AuditRecords());

        Assert.Equal(AuditDecisions.Allow, record.GetProperty("decision").GetString());
        Assert.Equal(JsonValueKind.Null, record.GetProperty("exit_code").ValueKind);
        Assert.False(string.IsNullOrEmpty(record.GetProperty("error").GetString()));
    }

    private static async Task<IReadOnlyList<string>> ListTools(AuthenticatedPipeline pipeline, string token)
    {
        var response = await pipeline.CallAsync(token, "tools/list", new { });

        return [.. response.GetProperty("result").GetProperty("tools").EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString()!)];
    }

    private static Task<JsonElement> CallRun(AuthenticatedPipeline pipeline, string token, string host)
        => pipeline.CallAsync(token, "tools/call", new
        {
            name = "run",
            arguments = new { host, cmd = "echo hello" },
        });

    private static bool IsError(JsonElement response)
        => response.TryGetProperty("result", out var result)
            && result.TryGetProperty("isError", out var isError)
            && isError.GetBoolean();

    private static string TextOf(JsonElement response)
        => response.GetRawText();

    /// <summary>A policy that answers the two questions independently.</summary>
    /// <remarks>
    /// Its whole purpose is that the answers can disagree. The real grant table derives both from
    /// one table, so it cannot tell a filter that asks one question from one that asks both.
    /// </remarks>
    private sealed class SplitPolicy : ISshWardenToolPolicy
    {
        public const string ToolRefusal = "stub_tool_refusal";
        public const string ArgumentRefusal = "stub_argument_refusal";

        private readonly bool _allowsTool;
        private readonly bool _allowsArguments;

        public SplitPolicy(bool allowsTool, bool allowsArguments)
        {
            _allowsTool = allowsTool;
            _allowsArguments = allowsArguments;
        }

        public AuthorizationDecision Allows(SshWarden.Auth.CallerIdentity caller, string tool)
            => _allowsTool
                ? AuthorizationDecision.Allow(AnyGrant)
                : AuthorizationDecision.Refuse(ToolRefusal, $"refused by the stub at the tool stage ({ToolRefusal})");

        public AuthorizationDecision AllowsArguments(
            SshWarden.Auth.CallerIdentity caller,
            string tool,
            IReadOnlyDictionary<string, JsonElement>? arguments)
            => _allowsArguments
                ? AuthorizationDecision.Allow(AnyGrant)
                : AuthorizationDecision.Refuse(ArgumentRefusal, $"refused by the stub at the argument stage ({ArgumentRefusal})");

        private static Grant AnyGrant => new()
        {
            Id = "stub",
            Subject = AuthenticatedPipeline.Subject,
            Tools = ["run"],
            Hosts = ["*"],
            SshUser = "nobody",
        };
    }
}
