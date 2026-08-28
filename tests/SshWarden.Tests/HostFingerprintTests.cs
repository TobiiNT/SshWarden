using System.Security.Cryptography;
using System.Text;

using SshWarden.Configuration;

using Xunit;

namespace SshWarden.Tests;

public sealed class HostFingerprintTests
{
    private static readonly byte[] HostKey = Encoding.UTF8.GetBytes("a host key, for the sake of argument");

    [Fact]
    public void The_fingerprint_of_a_key_matches_that_key()
        => Assert.True(HostFingerprint.Matches(Fingerprint(HostKey), HostKey));

    [Fact]
    public void The_fingerprint_of_one_key_does_not_match_another()
    {
        // The case that matters: a different machine answering on the address SshWarden was told to
        // connect to.
        var otherKey = Encoding.UTF8.GetBytes("a different host key");

        Assert.False(HostFingerprint.Matches(Fingerprint(HostKey), otherKey));
    }

    [Theory]
    [InlineData("not-a-fingerprint")]
    [InlineData("MD5:aa:bb:cc")]
    [InlineData("SHA256:")]
    [InlineData("SHA256:tooshort")]

    // Shorter than the prefix itself. Every case above is at least as long as "SHA256:", so the
    // decoder's unchecked slice at that offset was never reached with less to slice - and these
    // threw out of the host key callback instead of answering no, which is the one answer this
    // method promises for a value it cannot read.
    [InlineData("")]
    [InlineData("SHA256")]
    public void An_unusable_fingerprint_is_rejected_with_a_reason(string value)
    {
        Assert.False(HostFingerprint.IsValid(value, out var problem));
        Assert.NotEmpty(problem);

        // And it matches nothing, so a value that somehow got past startup validation cannot become
        // an accidental "yes". The safe answer to "I cannot tell" is no.
        Assert.False(HostFingerprint.Matches(value, HostKey));
    }

    [Fact]
    public void The_md5_form_openssh_also_prints_is_rejected()
    {
        // Rejected rather than accepted alongside SHA-256, so a deployment cannot downgrade its own
        // verification by pasting the wrong line out of the same command's output.
        Assert.False(HostFingerprint.IsValid("MD5:d4:1d:8c:d9:8f:00:b2:04:e9:80:09:98:ec:f8:42:7e", out _));
    }

    [Fact]
    public void The_unpadded_form_openssh_prints_is_accepted()
    {
        // Control, and the format that actually comes out of ssh-keygen -lf: base64 with the '='
        // padding stripped.
        var value = Fingerprint(HostKey);

        Assert.DoesNotContain('=', value);
        Assert.True(HostFingerprint.IsValid(value, out _));
    }

    private static string Fingerprint(byte[] key)
        => "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('=');
}
