using System.Text.Json;

using SshWarden.Auth;
using SshWarden.Authorization;

using Xunit;

namespace SshWarden.Tests;

/// <summary>
/// What the policy makes of a call's raw arguments.
/// </summary>
/// <remarks>
/// Tested here rather than only through the MCP layer, because the tools re-derive the same
/// decision for themselves - so a gate that stopped checking would still produce the right refusal
/// from one level down, and an end-to-end test could not tell. This is the level where the gate's
/// own answer is visible.
/// </remarks>
public sealed class GrantTableToolPolicyTests
{
    private static readonly Grant Reader = new()
    {
        Id = "prod-logs",
        Subject = "someone",
        Tools = ["read_file", "tail_log"],
        Hosts = ["prod-web-1"],
        Paths = ["/var/log/**"],
        Units = ["nginx*"],
        SshUser = "auditor",
    };

    [Fact]
    public void A_path_inside_the_grant_is_allowed()
    {
        // The control.
        var decision = Policy().AllowsArguments(
            Caller(), "read_file", Arguments(("host", "prod-web-1"), ("path", "/var/log/syslog")));

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void A_path_outside_the_grant_is_refused_by_the_gate_itself()
    {
        var decision = Policy().AllowsArguments(
            Caller(), "read_file", Arguments(("host", "prod-web-1"), ("path", "/etc/shadow")));

        Assert.Equal(AuthorizationRefusal.PathNotGranted, decision.RefusedBy);
    }

    [Fact]
    public void A_path_containing_dot_dot_is_refused_before_any_rule_is_consulted()
    {
        var decision = Policy().AllowsArguments(
            Caller(), "read_file", Arguments(("host", "prod-web-1"), ("path", "/var/log/../../etc/shadow")));

        Assert.Equal(AuthorizationRefusal.PathNotUsable, decision.RefusedBy);
    }

    [Fact]
    public void A_call_naming_no_path_is_refused_as_a_wiring_problem()
    {
        // Not "not granted": the gate could not find the argument it gates on, which no edit to the
        // grant table can fix.
        var decision = Policy().AllowsArguments(
            Caller(), "read_file", Arguments(("host", "prod-web-1")));

        Assert.Equal(AuthorizationRefusal.PathArgumentMissing, decision.RefusedBy);
    }

    [Fact]
    public void An_argument_without_a_leading_slash_is_read_as_a_unit()
    {
        // The rule somebody can hold in their head while reading a config file.
        Assert.True(Policy().AllowsArguments(
            Caller(), "tail_log", Arguments(("host", "prod-web-1"), ("unitOrPath", "nginx.service"))).IsAllowed);

        Assert.Equal(
            AuthorizationRefusal.UnitNotGranted,
            Policy().AllowsArguments(
                Caller(), "tail_log", Arguments(("host", "prod-web-1"), ("unitOrPath", "postgres.service"))).RefusedBy);
    }

    [Fact]
    public void A_tool_that_names_no_resource_is_decided_by_its_host_alone()
    {
        // `run` gates on the host and nothing else: its command is behaviour rather than a
        // resource, and its working directory is not a boundary because a command can change
        // directory freely.
        var table = new GrantTable([
            new Grant
            {
                Id = "exec",
                Subject = "someone",
                Tools = ["run"],
                Hosts = ["prod-web-1"],
                SshUser = "deploy",
            },
        ]);

        var decision = new GrantTableToolPolicy(table).AllowsArguments(
            Caller(), "run", Arguments(("host", "prod-web-1"), ("cmd", "cat /etc/shadow")));

        Assert.True(decision.IsAllowed);
    }

    private static GrantTableToolPolicy Policy() => new(new GrantTable([Reader]));

    private static Dictionary<string, JsonElement> Arguments(params (string Name, string Value)[] values)
        => values.ToDictionary(
            pair => pair.Name,
            pair => JsonSerializer.SerializeToElement(pair.Value),
            StringComparer.Ordinal);

    private static CallerIdentity Caller() => new()
    {
        Subject = "someone",
        ClientId = "a-client",
        GrantId = "a-grant",
        TokenId = "a-token",
        Source = "test",
        ScopeClaim = ScopeClaimState.Absent,
        Scopes = new HashSet<string>(StringComparer.Ordinal),
    };
}
