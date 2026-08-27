using System.Reflection;

using SshWarden.Audit;
using SshWarden.Auth;
using SshWarden.Authorization;
using SshWarden.Configuration;
using SshWarden.Metrics;

using Xunit;

namespace SshWarden.Tests;

/// <summary>What the exposition writes, and what it must never be made to write.</summary>
public sealed class PrometheusTextTests
{
    [Fact]
    public void Buckets_are_cumulative()
    {
        // The edge that bites. Written as "between these" rather than "at most this", a histogram
        // looks entirely plausible and answers every quantile wrong - and nothing downstream can
        // tell, because a scraper has no way to know what the numbers were supposed to be.
        var state = new HistogramState([1, 10, 100]);
        state.Observe(0.5);
        state.Observe(5);
        state.Observe(50);

        var text = Render("h", InstrumentKind.Histogram, histogram: state);

        Assert.Contains("h_bucket{le=\"1\"} 1", text, StringComparison.Ordinal);
        Assert.Contains("h_bucket{le=\"10\"} 2", text, StringComparison.Ordinal);
        Assert.Contains("h_bucket{le=\"100\"} 3", text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_infinite_bucket_is_the_total_rather_than_the_overflow()
    {
        // A scraper reads +Inf as the count. Writing the overflow bucket there instead is the other
        // classic way to produce a histogram whose quantiles are quietly nonsense.
        var state = new HistogramState([1]);
        state.Observe(0.5);
        state.Observe(900);

        var text = Render("h", InstrumentKind.Histogram, histogram: state);

        Assert.Contains("h_bucket{le=\"+Inf\"} 2", text, StringComparison.Ordinal);
        Assert.Contains("h_count 2", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_histogram_carries_its_own_labels_alongside_le()
    {
        var state = new HistogramState([1]);
        state.Observe(0.5);

        var text = Render("h", InstrumentKind.Histogram, labels: "host=\"a\"", histogram: state);

        // One set of braces, not two: `le` is a label like any other.
        Assert.Contains("h_bucket{host=\"a\",le=\"1\"} 1", text, StringComparison.Ordinal);
        Assert.Contains("h_sum{host=\"a\"}", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Numbers_do_not_ask_the_ambient_culture_what_a_decimal_point_is()
    {
        // A machine writing `0,05` produces a document no scraper accepts, and the failure surfaces
        // as a parse error somewhere else entirely.
        //
        // The separator is set on a clone of the invariant culture rather than by naming a locale,
        // because this deployable is built with InvariantGlobalization and `new CultureInfo("vi-VN")`
        // throws under it. That is worth saying rather than working around silently: in this host
        // the ambient culture cannot be the one that breaks this, so the invariant formatting is
        // belt-and-braces here - and it is not, for anything that ever hosts these assemblies
        // without that switch.
        var previous = Thread.CurrentThread.CurrentCulture;
        try
        {
            var comma = (System.Globalization.CultureInfo)System.Globalization.CultureInfo.InvariantCulture.Clone();
            comma.NumberFormat.NumberDecimalSeparator = ",";
            Thread.CurrentThread.CurrentCulture = comma;

            var state = new HistogramState([0.05]);
            state.Observe(0.01);

            var text = Render("h", InstrumentKind.Histogram, histogram: state);

            Assert.Contains("le=\"0.05\"", text, StringComparison.Ordinal);
            Assert.DoesNotContain("0,05", text, StringComparison.Ordinal);
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = previous;
        }
    }

    [Fact]
    public void A_label_value_cannot_break_out_of_its_quotes()
    {
        // Nothing should ever reach this - every label is clamped to a closed set before it gets
        // here - and it is tested because "should never" and "cannot" are different words. An
        // unescaped quote does not corrupt one line, it corrupts the parse from that point on.
        var escaped = PrometheusText.EscapeLabelValue("a\"b\\c\nd");

        Assert.Equal("a\\\"b\\\\c\\nd", escaped);
    }

    [Fact]
    public void Every_instrument_says_what_it_is()
    {
        // HELP and TYPE are what make a scrape readable by somebody who did not write it.
        var text = Render("c", InstrumentKind.Counter, counter: 3);

        Assert.Contains("# HELP c ", text, StringComparison.Ordinal);
        Assert.Contains("# TYPE c counter", text, StringComparison.Ordinal);
        Assert.Contains("c 3", text, StringComparison.Ordinal);
    }

    private static string Render(
        string name,
        InstrumentKind kind,
        string labels = "",
        long counter = 0,
        HistogramState? histogram = null)
    {
        var key = new SeriesKey(name, labels);

        return PrometheusText.Write(new MetricsSnapshot(
            [new InstrumentInfo(name, kind, "a description", histogram?.Bounds.ToArray() ?? [])],
            kind == InstrumentKind.Counter
                ? new Dictionary<SeriesKey, long> { [key] = counter }
                : new Dictionary<SeriesKey, long>(),
            new Dictionary<SeriesKey, double>(),
            histogram is null
                ? new Dictionary<SeriesKey, HistogramState>()
                : new Dictionary<SeriesKey, HistogramState> { [key] = histogram }));
    }
}

/// <summary>The instruments, and the label space they are allowed to occupy.</summary>
public sealed class SshWardenMetricsTests
{
    [Fact]
    public void A_host_nobody_declared_does_not_get_its_own_series()
    {
        // Cardinality is a memory budget somebody else can spend. A caller names the host on every
        // call and a refused call names a host that does not exist, so putting that string on a
        // label straight lets one caller mint one series per request - out of calls this server
        // correctly refuses - until the process runs out of memory.
        using var collector = new MetricsCollector();
        using var metrics = Metrics(out _);

        metrics.Observe(Record("dev-web-1", AuditDecisions.Allow));
        metrics.Observe(Record("../../etc/passwd", AuditDecisions.Deny));
        metrics.Observe(Record("attacker-chose-this", AuditDecisions.Deny));

        var text = PrometheusText.Write(collector.Snapshot());

        Assert.Contains("host=\"dev-web-1\"", text, StringComparison.Ordinal);
        Assert.Contains($"host=\"{SshWardenMetrics.Unknown}\"", text, StringComparison.Ordinal);
        Assert.DoesNotContain("attacker-chose-this", text, StringComparison.Ordinal);
        Assert.DoesNotContain("passwd", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_declared_host_does_get_its_own_series()
    {
        // The control. Without it the test above passes against a recorder that labels everything
        // unknown, which would make the metric useless in exactly the way it is meant to avoid.
        using var collector = new MetricsCollector();
        using var metrics = Metrics(out _);

        metrics.Observe(Record("dev-web-1", AuditDecisions.Allow));
        metrics.Observe(Record("prod-web-1", AuditDecisions.Allow));

        var text = PrometheusText.Write(collector.Snapshot());

        Assert.Contains("host=\"dev-web-1\"", text, StringComparison.Ordinal);
        Assert.Contains("host=\"prod-web-1\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_rule_this_server_does_not_define_does_not_get_its_own_series()
    {
        using var collector = new MetricsCollector();
        using var metrics = Metrics(out _);

        metrics.Observe(Record("dev-web-1", AuditDecisions.Deny, deniedBy: "host_not_granted"));
        metrics.Observe(Record("dev-web-1", AuditDecisions.Deny, deniedBy: "something-invented"));

        var text = PrometheusText.Write(collector.Snapshot());

        Assert.Contains("rule=\"host_not_granted\"", text, StringComparison.Ordinal);
        Assert.DoesNotContain("something-invented", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(AuditDecisions.Deny, null, null, "deny")]
    [InlineData(AuditDecisions.Allow, 0, null, "ok")]
    [InlineData(AuditDecisions.Allow, null, null, "ok")]
    [InlineData(AuditDecisions.Allow, 1, null, "fail")]
    [InlineData(AuditDecisions.Allow, null, "the connection dropped", "fail")]
    public void An_allowed_call_that_never_completed_is_a_failure(
        string decision, int? exitCode, string? error, string expected)
    {
        // The last row is why AuditRecord.Error exists. Without it a call that was allowed and then
        // failed looked exactly like a call with nothing to report an exit code about, so the one
        // number an operator alerts on could not be computed.
        var record = Record("dev-web-1", decision, exitCode: exitCode, error: error);

        Assert.Equal(expected, SshWardenMetrics.Outcome(record));
    }

    [Fact]
    public void Nothing_with_an_unbounded_value_set_reaches_a_label()
    {
        // docs/DESIGN.md §4.7 names these: every one is a field that takes a new value per
        // session or per call, and every one looks like a natural label. They stay in the JSON body,
        // where a query filters them without indexing them.
        using var collector = new MetricsCollector();
        using var metrics = Metrics(out _);

        metrics.Observe(Record(
            "dev-web-1",
            AuditDecisions.Allow,
            subject: "a-subject",
            grantId: "sw_gid_unbounded",
            tokenId: "sw_jti_unbounded",
            command: "a-command",
            workdir: "/a/workdir"));

        var text = PrometheusText.Write(collector.Snapshot());

        foreach (var forbidden in new[]
        {
            "a-subject", "sw_gid_unbounded", "sw_jti_unbounded", "a-command", "/a/workdir",
        })
        {
            Assert.DoesNotContain(forbidden, text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_surface_is_the_six_that_were_agreed()
    {
        // Closed on purpose: it is what makes writing the exposition by hand a bounded job rather
        // than an open-ended one, and a seventh added without noticing is how that stops being true.
        using var collector = new MetricsCollector();
        using var metrics = Metrics(out _);

        metrics.Observe(Record("dev-web-1", AuditDecisions.Allow));

        var names = collector.Snapshot().Instruments.Select(i => i.Name).OrderBy(n => n, StringComparer.Ordinal);

        Assert.Equal(
            [
                "sshwarden_command_duration_seconds",
                "sshwarden_commands_total",
                "sshwarden_denied_total",
                "sshwarden_output_bytes",
                "sshwarden_output_truncated_total",
                "sshwarden_pool_connections_active",
            ],
            names);
    }

    [Fact]
    public void The_pool_gauge_is_read_when_somebody_asks()
    {
        // Observable rather than written from wherever a connection happens to open: a gauge
        // maintained by hand drifts the first time a path forgets to decrement it.
        using var collector = new MetricsCollector();
        using var metrics = Metrics(out var connections);

        connections.Value = 3;
        Assert.Contains("sshwarden_pool_connections_active 3", PrometheusText.Write(collector.Snapshot()), StringComparison.Ordinal);

        connections.Value = 1;
        Assert.Contains("sshwarden_pool_connections_active 1", PrometheusText.Write(collector.Snapshot()), StringComparison.Ordinal);
    }

    [Fact]
    public void The_output_histogram_has_the_cap_as_a_boundary()
    {
        // The whole reason this instrument exists: docs/DESIGN.md §4.5 left "is the 64 KiB cap
        // right" open, and it is answerable only by reading how much of the distribution sits above
        // that exact line. A bucket set that straddles it answers nothing.
        Assert.Contains(65536d, SshWardenMetrics.OutputByteBuckets);
    }

    private static SshWardenMetrics Metrics(out StrongBoxInt connections)
    {
        var box = new StrongBoxInt();
        connections = box;

        return new SshWardenMetrics(
            new HostRegistry([
                new HostEntry { Name = "dev-web-1", Fingerprint = Fingerprint },
                new HostEntry { Name = "prod-web-1", Fingerprint = Fingerprint },
            ]),
            () => box.Value);
    }

    private const string Fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    private static AuditRecord Record(
        string host,
        string decision,
        string? deniedBy = null,
        int? exitCode = null,
        string? error = null,
        string subject = "someone",
        string grantId = "sw_gid_test",
        string tokenId = "sw_jti_test",
        string? command = null,
        string? workdir = null) => new()
    {
        Id = "sw_rec_test",
        Type = AuditRecordTypes.Command,
        StartedAt = DateTimeOffset.UnixEpoch,
        Subject = subject,
        ClientId = "test",
        GrantId = grantId,
        TokenId = tokenId,
        Tool = ToolNames.Run,
        Decision = decision,
        DeniedBy = deniedBy
            ?? (decision == AuditDecisions.Deny ? AuthorizationRefusal.HostNotGranted : null),
        Host = host,
        ExitCode = exitCode,
        Error = error,
        Command = command,
        Workdir = workdir,
    };

    internal sealed class StrongBoxInt
    {
        public int Value { get; set; }
    }
}

/// <summary>The closed sets the labels rest on.</summary>
public sealed class ClosedLabelSetTests
{
    [Fact]
    public void Every_refusal_reason_is_in_the_list_that_claims_to_hold_them_all()
    {
        // A list kept by hand is a list that is right until the next one is added, and this one
        // carries a security property: it is what bounds a metric label's value set.
        var declared = typeof(AuthorizationRefusal)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.FieldType == typeof(string) && field.IsLiteral)
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToList();

        Assert.NotEmpty(declared);
        Assert.Equal(
            declared.OrderBy(v => v, StringComparer.Ordinal),
            AuthorizationRefusal.All.OrderBy(v => v, StringComparer.Ordinal));
    }
}
