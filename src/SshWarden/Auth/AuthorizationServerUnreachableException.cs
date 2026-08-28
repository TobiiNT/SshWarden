namespace SshWarden.Auth;

/// <summary>The authorization server could not be reached while the process was starting.</summary>
/// <remarks>
/// <para>
/// <strong>Here rather than inside the OAuth adapter that raises it.</strong> It began inside an
/// adapter, which made it unreachable from anything a deployment writes itself - so a second
/// implementation would have had to invent its own type, and the host would have needed a catch
/// clause per adapter to print one message.
/// </para>
/// <para>
/// Its own type so the host can tell it from a defect. Both arrive at the same place - an exception
/// out of <c>StartAsync</c> - and they want opposite responses: a bug should print where it came
/// from, and this should print one line naming the server that did not answer, because the stack
/// trace behind it is this process's plumbing rather than anything an operator can act on.
/// </para>
/// <para>
/// <strong>A restart is the right response to this one</strong>, which is the other half of the
/// distinction. A bad config will fail identically forever; an authorization server that is still
/// booting, or briefly unreachable, will not - so the host exits with a code that says so rather
/// than with the one that tells a supervisor to give up.
/// </para>
/// </remarks>
public sealed class AuthorizationServerUnreachableException : Exception
{
    /// <summary>Creates one with no message.</summary>
    public AuthorizationServerUnreachableException()
    {
    }

    /// <summary>Creates one carrying <paramref name="message" />.</summary>
    /// <param name="message">What could not be reached, and why it stops startup.</param>
    public AuthorizationServerUnreachableException(string message)
        : base(message)
    {
    }

    /// <summary>Creates one carrying <paramref name="message" /> and the failure under it.</summary>
    /// <param name="message">What could not be reached, and why it stops startup.</param>
    /// <param name="innerException">The failure that produced it.</param>
    public AuthorizationServerUnreachableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
