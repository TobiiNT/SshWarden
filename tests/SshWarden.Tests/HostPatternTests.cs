using SshWarden.Authorization;

using Xunit;

namespace SshWarden.Tests;

public sealed class HostPatternTests
{
    [Theory]
    [InlineData("prod-web-1", "prod-web-1")]
    [InlineData("dev-*", "dev-web-1")]
    [InlineData("dev-*", "dev-")]
    [InlineData("*", "anything")]
    [InlineData("web-?", "web-1")]
    [InlineData("PROD-WEB-1", "prod-web-1")]
    [InlineData("db.example.test", "db.example.test")]
    [InlineData("*.example.test", "db.example.test")]
    public void A_matching_host_matches(string pattern, string host)
        => Assert.True(HostPattern.Matches(pattern, host));

    [Theory]
    [InlineData("dev-*", "prod-web-1")]
    [InlineData("web-?", "web-12")]
    [InlineData("prod-web-1", "prod-web-2")]
    public void A_non_matching_host_does_not(string pattern, string host)
        => Assert.False(HostPattern.Matches(pattern, host));

    [Theory]
    [InlineData("dev-*", "dev.internal")]
    [InlineData("*", "db.example.test")]
    [InlineData("prod-*", "prod-web.customer.example")]
    public void A_star_does_not_cross_a_dot(string pattern, string host)
    {
        // The rule that stops a pattern written for a short name from widening to a whole domain
        // the day somebody starts using fully qualified ones. Without it, 'prod-*' would cover
        // 'prod-web.someone-elses.example' - a machine the rule was never about.
        Assert.False(HostPattern.Matches(pattern, host));
    }

    [Fact]
    public void A_shorter_pattern_does_not_match_a_longer_host()
    {
        // Same rule from the other side: label counts have to agree, so 'dev-web' does not also
        // cover 'dev-web.customer.example'.
        Assert.False(HostPattern.Matches("dev-web", "dev-web.customer.example"));
    }

    [Theory]
    [InlineData("*******************************a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab")]
    [InlineData("a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void A_pathological_pattern_still_answers(string pattern, string host)
    {
        // The input that turns the obvious backtracking matcher into the denial of service that
        // choosing glob over regex was supposed to avoid. Asserting the answer rather than the time
        // it took, because a timing assertion is a flake: what this proves is that the matcher
        // terminates on the shape that would not.
        Assert.False(HostPattern.Matches(pattern, host));
    }

    [Theory]
    [InlineData("", "is empty")]
    [InlineData("a..b", "empty label")]
    [InlineData("prod.**", "'**'")]
    public void An_unusable_pattern_is_rejected_with_a_reason(string pattern, string expected)
    {
        Assert.False(HostPattern.IsValid(pattern, out var problem));
        Assert.Contains(expected, problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("dev-*")]
    [InlineData("prod-web-1")]
    [InlineData("*.example.test")]
    public void A_usable_pattern_is_accepted(string pattern)
    {
        // Control for the rule above: a validator that rejected everything would look like a
        // working one.
        Assert.True(HostPattern.IsValid(pattern, out _));
    }
}
