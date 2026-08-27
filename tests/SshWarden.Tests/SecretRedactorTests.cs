using SshWarden.Output;

using Xunit;

namespace SshWarden.Tests;

public sealed class SecretRedactorTests
{
    [Theory]
    [InlineData("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id")]
    [InlineData("ghp_0123456789012345678901234567890123456", "github-token")]
    [InlineData("sk-abcdefghijklmnopqrstuvwxyz012345", "api-key")]
    [InlineData("xoxb-0123456789-abcdefghij", "slack-token")]
    [InlineData("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27u", "json-web-token")]
    [InlineData("Bearer abcdefghijklmnopqrstuvwxyz0123", "bearer-credential")]
    public void A_credential_shaped_value_is_masked(string secret, string expectedLabel)
    {
        var result = SecretRedactor.Redact($"before {secret} after");

        // The value goes entirely. Never a prefix and never a length hint: a partial credential in
        // a log is a whole credential to somebody who can guess the rest.
        Assert.DoesNotContain(secret, result.Text, StringComparison.Ordinal);
        Assert.Contains(expectedLabel, result.Text, StringComparison.Ordinal);
        Assert.Equal(1, result.Count);

        // And the surrounding text survives, because output nobody can read is output that gets the
        // redactor turned off.
        Assert.Contains("before ", result.Text, StringComparison.Ordinal);
        Assert.Contains(" after", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_private_key_block_is_masked_whole()
    {
        var text = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
            c2gtZWQyNTUxOQAAACBjZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5AAAA
            -----END OPENSSH PRIVATE KEY-----
            """;

        var result = SecretRedactor.Redact("head\n" + text + "\ntail");

        // Taken as one block. The interior is base64 that matches none of the narrow patterns, so
        // line-by-line masking would leave the whole key behind.
        Assert.DoesNotContain("b3BlbnNzaC1rZXktdjEA", result.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN OPENSSH", result.Text, StringComparison.Ordinal);
        Assert.Contains("head", result.Text, StringComparison.Ordinal);
        Assert.Contains("tail", result.Text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("API_TOKEN=abcdef123456")]
    [InlineData("export DB_PASSWORD='s3cr3t'")]
    [InlineData("  aws_secret_access_key = wJalrXUtnFEMI")]
    [InlineData("MY_APP_CREDENTIALS=anything at all")]
    public void A_secret_shaped_assignment_keeps_its_name_and_loses_its_value(string line)
    {
        var result = SecretRedactor.Redact(line);

        Assert.Contains("[redacted: secret-assignment]", result.Text, StringComparison.Ordinal);

        // The name survives. A reader still needs to know *which* setting was there - that is what
        // turns a redacted line into a useful one rather than a blank.
        var name = line.Split('=')[0].Trim().Replace("export ", string.Empty, StringComparison.Ordinal);
        Assert.Contains(name, result.Text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("PATH=/usr/local/bin:/usr/bin")]
    [InlineData("HOME=/root")]
    [InlineData("total 48")]
    [InlineData("drwxr-xr-x 2 root root 4096 Aug 26 05:00 logs")]
    public void Ordinary_output_is_left_alone(string line)
    {
        // The control, and the one that decides whether this feature survives contact with use.
        // A redactor that eats `echo PATH=...` produces unreadable output, and an unreadable
        // redactor gets switched off - which protects nothing at all.
        var result = SecretRedactor.Redact(line);

        Assert.Equal(line, result.Text);
        Assert.Equal(0, result.Count);
    }

    [Fact]
    public void A_password_in_a_url_goes_and_the_rest_of_the_url_stays()
    {
        var result = SecretRedactor.Redact("postgres://appuser:hunter2@db.example.test:5432/app");

        Assert.DoesNotContain("hunter2", result.Text, StringComparison.Ordinal);

        // The host and the user stay readable - those are what somebody debugging a connection
        // actually needs, and masking them would cost the whole line's usefulness for nothing.
        Assert.Contains("appuser", result.Text, StringComparison.Ordinal);
        Assert.Contains("db.example.test:5432/app", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_url_without_credentials_is_left_alone()
    {
        const string Url = "https://docs.example.test/guide#section";

        Assert.Equal(Url, SecretRedactor.Redact(Url).Text);
    }

    [Fact]
    public void Several_values_on_one_line_are_all_masked_and_counted()
    {
        var result = SecretRedactor.Redact("AKIAIOSFODNN7EXAMPLE and ghp_0123456789012345678901234567890123456");

        Assert.Equal(2, result.Count);
        Assert.DoesNotContain("AKIA", result.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("ghp_", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_text_is_left_alone()
        => Assert.Equal(string.Empty, SecretRedactor.Redact(string.Empty).Text);
}
