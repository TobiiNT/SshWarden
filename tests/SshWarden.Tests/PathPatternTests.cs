using SshWarden.Authorization;

using Xunit;

namespace SshWarden.Tests;

public sealed class PathPatternTests
{
    [Theory]
    [InlineData("/var/log/*", "/var/log/syslog")]
    [InlineData("/var/log/**", "/var/log/syslog")]
    [InlineData("/var/log/**", "/var/log/nginx/access.log")]
    [InlineData("/var/log/**", "/var/log")]
    [InlineData("/etc/nginx/*.conf", "/etc/nginx/nginx.conf")]
    [InlineData("/**", "/anything/at/all")]
    [InlineData("/opt/app-?/log", "/opt/app-1/log")]
    public void A_matching_path_matches(string pattern, string path)
        => Assert.True(PathPattern.Matches(pattern, path));

    [Theory]
    [InlineData("/var/log/*", "/var/log/nginx/access.log")]
    [InlineData("/var/log/**", "/var/lib/thing")]
    [InlineData("/etc/nginx/*.conf", "/etc/nginx/sites/a.conf")]
    [InlineData("/var/log/syslog", "/var/log/syslog.1")]
    public void A_non_matching_path_does_not(string pattern, string path)
        => Assert.False(PathPattern.Matches(pattern, path));

    [Fact]
    public void A_single_star_does_not_cross_a_slash()
    {
        // The rule that stops a pattern written for one directory from covering everything beneath
        // it. `/var/log/*` is the log files; `/var/log/**` is the tree, and somebody has to say so.
        Assert.False(PathPattern.Matches("/var/log/*", "/var/log/nginx/access.log"));
        Assert.True(PathPattern.Matches("/var/log/**", "/var/log/nginx/access.log"));
    }

    [Fact]
    public void Matching_is_case_sensitive()
    {
        // Unlike host names, which RFC 4343 makes case-insensitive. Unix paths are two different
        // files, and folding case here would make a rule cover something it does not name.
        Assert.False(PathPattern.Matches("/etc/passwd", "/etc/Passwd"));
    }

    [Theory]
    [InlineData("/a/**/**/**/**/**/**/b", "/a/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/c")]
    public void A_pathological_pattern_still_answers(string pattern, string path)
    {
        // The shape that turns a recursive matcher exponential - and it is what somebody writes
        // when being careful, not when attacking. Asserting the answer rather than the time: a
        // timing assertion is a flake, and what this proves is that it terminates.
        Assert.False(PathPattern.Matches(pattern, path));
    }

    [Theory]
    [InlineData("var/log/**", "is not absolute")]
    [InlineData("/var/../etc", "contains '..'")]
    [InlineData("/var/log**", "'**' inside a segment")]
    [InlineData("/var//log", "empty segment")]
    public void An_unusable_pattern_is_rejected_with_a_reason(string pattern, string expected)
    {
        Assert.False(PathPattern.IsValid(pattern, out var problem));
        Assert.Contains(expected, problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/var/log/**")]
    [InlineData("/etc/nginx/*.conf")]
    [InlineData("/opt/app/log/current")]
    public void A_usable_pattern_is_accepted(string pattern)
        => Assert.True(PathPattern.IsValid(pattern, out _));

    [Theory]
    [InlineData("/var/log/syslog", "/var/log/syslog")]
    [InlineData("/var//log///syslog", "/var/log/syslog")]
    [InlineData("/var/log/syslog/", "/var/log/syslog")]
    [InlineData("/var/./log/syslog", "/var/log/syslog")]
    public void A_path_is_normalized_to_one_form(string path, string expected)
    {
        Assert.True(PathPattern.TryNormalize(path, out var normalized, out _));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("/var/log/../../etc/shadow")]
    [InlineData("/..")]
    [InlineData("/var/log/..")]
    public void A_path_containing_dot_dot_is_refused_rather_than_resolved(string path)
    {
        // Refused, not resolved, and that is the stronger answer: resolving means the string a rule
        // was checked against and the string the caller wrote are different, and every later reader
        // has to work out which one they are looking at. No caller naming a file it may read needs
        // to walk upwards to get there.
        Assert.False(PathPattern.TryNormalize(path, out _, out var problem));
        Assert.Contains("'..'", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_relative_path_is_refused()
    {
        Assert.False(PathPattern.TryNormalize("log/syslog", out _, out var problem));
        Assert.Contains("absolute", problem, StringComparison.Ordinal);
    }
}

public sealed class UnitPatternTests
{
    [Theory]
    [InlineData("nginx.service", "nginx.service")]
    [InlineData("nginx*", "nginx.service")]
    [InlineData("*", "getty@tty1.service")]
    [InlineData("getty@*", "getty@tty1.service")]
    public void A_matching_unit_matches(string pattern, string unit)
        => Assert.True(UnitPattern.Matches(pattern, unit));

    [Fact]
    public void A_dot_is_part_of_the_name_rather_than_a_separator()
    {
        // The reason units do not reuse the host matcher. A host glob matches label by label and
        // requires the counts to agree, so `nginx*` would fail against `nginx.service` - which is
        // the first pattern anybody writes.
        Assert.True(UnitPattern.Matches("nginx*", "nginx.service"));
        Assert.False(HostPattern.Matches("nginx*", "nginx.service"));
    }

    [Theory]
    [InlineData("nginx.service", "postgres.service")]
    [InlineData("nginx", "nginx.service")]
    public void A_non_matching_unit_does_not(string pattern, string unit)
        => Assert.False(UnitPattern.Matches(pattern, unit));

    [Fact]
    public void A_pattern_containing_a_slash_is_rejected()
    {
        Assert.False(UnitPattern.IsValid("/var/log/syslog", out var problem));
        Assert.Contains("paths", problem, StringComparison.Ordinal);
    }
}
