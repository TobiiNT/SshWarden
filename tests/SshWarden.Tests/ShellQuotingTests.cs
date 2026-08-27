using SshWarden.Ssh;

using Xunit;

namespace SshWarden.Tests;

public sealed class ShellQuotingTests
{
    [Theory]
    [InlineData("plain", "'plain'")]
    [InlineData("with space", "'with space'")]
    [InlineData("$HOME", "'$HOME'")]
    [InlineData("`id`", "'`id`'")]
    [InlineData("a\\b", "'a\\b'")]
    [InlineData("it's", "'it'\\''s'")]
    [InlineData("'; rm -rf /; '", "''\\''; rm -rf /; '\\'''")]
    public void A_value_becomes_one_literal_shell_word(string value, string expected)
        => Assert.Equal(expected, ShellQuoting.Quote(value));

    [Fact]
    public void A_quoted_value_cannot_reopen_the_quote()
    {
        // The property that matters, stated without reference to a particular input: after quoting,
        // every quote character in the result is either the pair this added or part of the escape
        // sequence - so nothing the caller wrote can end the literal early and start being code.
        const string Hostile = "'$(id)'`id`\"; id; \"";

        var quoted = ShellQuoting.Quote(Hostile);

        Assert.StartsWith("'", quoted, StringComparison.Ordinal);
        Assert.EndsWith("'", quoted, StringComparison.Ordinal);

        // Strip the wrapping pair and every properly escaped quote; nothing quote-shaped may remain.
        var inner = quoted[1..^1].Replace("'\\''", string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain('\'', inner);
    }

    [Theory]
    [InlineData("PATH")]
    [InlineData("_private")]
    [InlineData("A1")]
    public void A_usable_environment_name_is_accepted(string name)
        => Assert.True(ShellQuoting.IsValidEnvironmentName(name));

    [Theory]
    [InlineData("")]
    [InlineData("1FIRST")]
    [InlineData("has space")]
    [InlineData("has-dash")]
    [InlineData("A=B")]
    public void An_unusable_environment_name_is_rejected(string name)
    {
        // 'A=B' is the one worth naming. It is refused rather than quoted, because env splits
        // NAME=VALUE on the first '=' itself - so however well the word is quoted for the shell,
        // that name would set variable 'A' to 'B=<value>' instead of the variable asked for.
        Assert.False(ShellQuoting.IsValidEnvironmentName(name));
    }
}
