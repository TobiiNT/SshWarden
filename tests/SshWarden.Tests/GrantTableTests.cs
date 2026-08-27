using SshWarden.Auth;
using SshWarden.Authorization;

using Xunit;

namespace SshWarden.Tests;

public sealed class GrantTableTests
{
    private static readonly Grant ExecOnDev = new()
    {
        Id = "dev-exec",
        Subject = "someone",
        Scopes = ["ssh:exec"],
        Tools = ["run", "start_job"],
        Hosts = ["dev-*"],
        SshUser = "deploy",
    };

    private static readonly Grant ReadOnProd = new()
    {
        Id = "prod-read",
        Subject = "someone",
        Scopes = ["ssh:read"],
        Tools = ["read_file", "tail_log"],
        Hosts = ["prod-web-1"],
        SshUser = "auditor",
    };

    [Fact]
    public void A_covered_call_is_allowed_and_names_the_rule()
    {
        var decision = Table().AuthorizeHost(Caller(), "run", "dev-web-1");

        Assert.True(decision.IsAllowed);
        Assert.Equal("dev-exec", decision.Grant!.Id);

        // The unix account comes from the rule, and it is the whole reason an allowed decision has
        // to carry which rule allowed it rather than just 'yes'.
        Assert.Equal("deploy", decision.Grant.SshUser);
    }

    [Fact]
    public void A_call_with_no_rule_at_all_is_refused()
    {
        var decision = new GrantTable([]).AuthorizeTool(Caller(), "run");

        Assert.False(decision.IsAllowed);
        Assert.Equal(AuthorizationRefusal.NoGrantForSubject, decision.RefusedBy);
    }

    [Fact]
    public void A_subject_with_rules_but_not_this_tool_is_refused_at_the_tool()
    {
        // The refusal names the stage that failed, not just 'denied'. "A rule names them but not
        // this tool" and "no rule names them at all" want different responses from whoever reads
        // the log.
        var decision = Table().AuthorizeTool(Caller(), "list_changes");

        Assert.Equal(AuthorizationRefusal.ToolNotGranted, decision.RefusedBy);
    }

    [Fact]
    public void A_tool_that_is_granted_on_another_host_is_refused_at_the_host()
    {
        var decision = Table().AuthorizeHost(Caller(), "run", "prod-web-1");

        Assert.Equal(AuthorizationRefusal.HostNotGranted, decision.RefusedBy);
    }

    [Fact]
    public void A_different_subject_is_refused()
    {
        var decision = Table().AuthorizeTool(Caller(subject: "someone-else"), "run");

        Assert.Equal(AuthorizationRefusal.NoGrantForSubject, decision.RefusedBy);
    }

    [Fact]
    public void A_subject_is_compared_ordinally()
    {
        // Not case-folded. A subject identifier from an authorization server is opaque, and two
        // that differ in case are two subjects - assuming otherwise would hand one person's grants
        // to another.
        Assert.Equal(
            AuthorizationRefusal.NoGrantForSubject,
            Table().AuthorizeTool(Caller(subject: "SOMEONE"), "run").RefusedBy);
    }

    [Fact]
    public void A_token_with_no_scope_claim_falls_back_to_the_grant_table()
    {
        // The legitimate case: a static token, or an authorization server that publishes no scopes.
        // The rule's own scope list is waived and everything else still has to match.
        var decision = Table().AuthorizeHost(Caller(ScopeClaimState.Absent), "run", "dev-web-1");

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void A_token_whose_scope_claim_could_not_be_read_is_refused()
    {
        // The fail-open this design exists to close. An unparseable claim yields the same empty set
        // as no claim at all; if it fell back like the case above, a mangled token would be granted
        // more than it asked for.
        var decision = Table().AuthorizeHost(Caller(ScopeClaimState.Unreadable), "run", "dev-web-1");

        Assert.Equal(AuthorizationRefusal.UnreadableScopeClaim, decision.RefusedBy);
    }

    [Fact]
    public void A_token_whose_scope_claim_is_empty_is_refused()
    {
        // A token minted with an empty scope set was written to grant nothing. Reading it as "said
        // nothing" would widen it to whatever the grant table allows.
        var decision = Table().AuthorizeHost(
            Caller(ScopeClaimState.Readable, scopes: []),
            "run",
            "dev-web-1");

        Assert.Equal(AuthorizationRefusal.EmptyScopeClaim, decision.RefusedBy);
    }

    [Fact]
    public void A_token_missing_the_scope_a_rule_needs_is_refused_at_the_scope()
    {
        // The one refusal here that re-authorizing can fix, which is why it is distinguishable from
        // the rest - every other identifier means somebody has to change the server's config.
        var decision = Table().AuthorizeHost(
            Caller(ScopeClaimState.Readable, scopes: ["ssh:read"]),
            "run",
            "dev-web-1");

        Assert.Equal(AuthorizationRefusal.ScopeNotGranted, decision.RefusedBy);
    }

    [Fact]
    public void A_token_carrying_the_scope_a_rule_needs_is_allowed()
    {
        // Control for the four scope refusals above.
        var decision = Table().AuthorizeHost(
            Caller(ScopeClaimState.Readable, scopes: ["ssh:exec"]),
            "run",
            "dev-web-1");

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void A_rule_needing_two_scopes_needs_both()
    {
        var table = new GrantTable([
            Exec("both", ["ssh:exec", "ssh:admin"], "deploy"),
        ]);

        Assert.Equal(
            AuthorizationRefusal.ScopeNotGranted,
            table.AuthorizeHost(Caller(ScopeClaimState.Readable, scopes: ["ssh:exec"]), "run", "dev-web-1").RefusedBy);

        Assert.True(
            table.AuthorizeHost(Caller(ScopeClaimState.Readable, scopes: ["ssh:exec", "ssh:admin"]), "run", "dev-web-1")
                .IsAllowed);
    }

    [Fact]
    public void The_first_matching_rule_in_file_order_wins()
    {
        // Two rules can cover one host with two different unix accounts, and something has to
        // choose. File order, documented, rather than refusing the ambiguity - which would turn a
        // working config into a startup failure the day somebody adds an overlapping rule.
        var table = new GrantTable([
            ExecOnDev,
            Exec("second", ["ssh:exec"], "other"),
        ]);

        Assert.Equal("dev-exec", table.AuthorizeHost(Caller(), "run", "dev-web-1").Grant!.Id);
    }

    [Fact]
    public void A_refusal_does_not_name_what_would_have_worked()
    {
        // A refusal that listed the hosts or subjects that are configured would be a way to
        // enumerate the deployment from outside it.
        var detail = Table().AuthorizeHost(Caller(), "run", "prod-db-9").Detail!;

        Assert.DoesNotContain("dev-", detail, StringComparison.Ordinal);
        Assert.DoesNotContain("deploy", detail, StringComparison.Ordinal);
        Assert.DoesNotContain("auditor", detail, StringComparison.Ordinal);

        // It does say what was refused and which rule refused it.
        Assert.Contains("run", detail, StringComparison.Ordinal);
        Assert.Contains(AuthorizationRefusal.HostNotGranted, detail, StringComparison.Ordinal);
    }

    [Fact]
    public void A_path_a_rule_covers_is_allowed()
    {
        var table = new GrantTable([Reader()]);

        Assert.True(table.AuthorizePath(Caller(), "read_file", "prod-web-1", "/var/log/syslog").IsAllowed);
    }

    [Fact]
    public void A_path_no_rule_covers_is_refused_at_the_path()
    {
        var decision = new GrantTable([Reader()])
            .AuthorizePath(Caller(), "read_file", "prod-web-1", "/etc/shadow");

        Assert.Equal(AuthorizationRefusal.PathNotGranted, decision.RefusedBy);
    }

    [Fact]
    public void One_rule_has_to_cover_both_the_host_and_the_path()
    {
        // Two rules covering one each must not combine. A caller allowed the logs on a development
        // machine and allowed a production machine for something else would otherwise get
        // production logs out of the pair.
        var table = new GrantTable([
            new Grant
            {
                Id = "dev-logs",
                Subject = "someone",
                Tools = ["read_file"],
                Hosts = ["dev-*"],
                Paths = ["/var/log/**"],
                SshUser = "auditor",
            },
            new Grant
            {
                Id = "prod-app",
                Subject = "someone",
                Tools = ["read_file"],
                Hosts = ["prod-web-1"],
                Paths = ["/opt/app/**"],
                SshUser = "deploy",
            },
        ]);

        Assert.Equal(
            AuthorizationRefusal.PathNotGranted,
            table.AuthorizePath(Caller(), "read_file", "prod-web-1", "/var/log/syslog").RefusedBy);

        // And each rule still works on its own - the control that says this is not just refusing
        // everything.
        Assert.True(table.AuthorizePath(Caller(), "read_file", "dev-web-1", "/var/log/syslog").IsAllowed);
        Assert.True(table.AuthorizePath(Caller(), "read_file", "prod-web-1", "/opt/app/x").IsAllowed);
    }

    [Fact]
    public void A_unit_a_rule_covers_is_allowed_and_one_it_does_not_is_refused()
    {
        var table = new GrantTable([Reader()]);

        Assert.True(table.AuthorizeUnit(Caller(), "tail_log", "prod-web-1", "nginx.service").IsAllowed);
        Assert.Equal(
            AuthorizationRefusal.UnitNotGranted,
            table.AuthorizeUnit(Caller(), "tail_log", "prod-web-1", "postgres.service").RefusedBy);
    }

    [Fact]
    public void A_path_refusal_does_not_name_what_would_have_worked()
    {
        var detail = new GrantTable([Reader()])
            .AuthorizePath(Caller(), "read_file", "prod-web-1", "/etc/shadow").Detail!;

        Assert.DoesNotContain("/var/log", detail, StringComparison.Ordinal);
        Assert.DoesNotContain("auditor", detail, StringComparison.Ordinal);
        Assert.Contains(AuthorizationRefusal.PathNotGranted, detail, StringComparison.Ordinal);
    }

    private static Grant Reader() => new()
    {
        Id = "prod-logs",
        Subject = "someone",
        Tools = ["read_file", "tail_log"],
        Hosts = ["prod-web-1"],
        Paths = ["/var/log/**"],
        Units = ["nginx*"],
        SshUser = "auditor",
    };

    private static Grant Exec(string id, string[] scopes, string sshUser) => new()
    {
        Id = id,
        Subject = "someone",
        Scopes = scopes,
        Tools = ["run", "start_job"],
        Hosts = ["dev-*"],
        SshUser = sshUser,
    };

    private static GrantTable Table() => new([ExecOnDev, ReadOnProd]);

    private static CallerIdentity Caller(
        ScopeClaimState state = ScopeClaimState.Absent,
        string subject = "someone",
        string[]? scopes = null)
        => new()
        {
            Subject = subject,
            ClientId = "a-client",
            GrantId = "a-grant",
            TokenId = "a-token",
            Source = "test",
            ScopeClaim = state,
            Scopes = new HashSet<string>(scopes ?? [], StringComparer.Ordinal),
        };
}
