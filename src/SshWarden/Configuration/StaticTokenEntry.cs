namespace SshWarden.Configuration;

/// <summary>One configured static token: a credential and the identity it stands for.</summary>
/// <remarks>
/// <para>
/// The five values of <see cref="Auth.CallerIdentity" /> have to come from somewhere for a
/// deployment with no authorization server. Two are declared here, and the other two are derived at
/// startup - see <see cref="Auth.StaticTokenAuthenticator" /> for what is derived and why that is
/// honest rather than invented.
/// </para>
/// </remarks>
public sealed class StaticTokenEntry
{
    /// <summary>
    /// What this token is for, in the operator's words - which laptop, which CI job, which client.
    /// </summary>
    /// <remarks>
    /// Required, unique, and the thing every refusal and every startup message names, because
    /// "token 3 of 5" is not something anybody can act on. It is also the default
    /// <see cref="ClientId" />.
    /// </remarks>
    public required string Name { get; init; }

    /// <summary>Who this token acts as. Written to the audit record as <c>sub</c>.</summary>
    /// <remarks>
    /// <para>
    /// Declared per token rather than being a constant, and that is a correction to an earlier draft
    /// of the design, which had every static token report the literal subject <c>static</c>. The
    /// grant table of docs/DESIGN.md §6.5.4 is keyed on the subject; a constant collapses every static
    /// identity in a deployment into one row, so a deployment could never give its CI job narrower
    /// reach than its laptop. Two tokens may share a subject deliberately - that is two credentials
    /// for one person - but it has to be the operator's choice.
    /// </para>
    /// </remarks>
    public required string Subject { get; init; }

    /// <summary>The credential itself.</summary>
    /// <remarks>
    /// <para>
    /// Compared in constant time and never logged, never echoed in an error, and never written to
    /// the audit record - not even a prefix of it. docs/DESIGN.md §6.1 requires this to arrive from a
    /// mode-0600 file rather than a command-line argument, because an argument is readable by every
    /// process on the box through <c>ps</c>.
    /// </para>
    /// <para>
    /// A static token does not expire. That is the argument for moving to the OAuth authenticator
    /// at step 8 rather than a defect in this one, and it is why the config loader insists the
    /// credential be long enough that guessing it is not a strategy.
    /// </para>
    /// </remarks>
    public required string Token { get; init; }

    /// <summary>
    /// Which client to record. Defaults to <see cref="Name" /> when the config does not say.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A static token has no OAuth client behind it, so this is the nearest true answer rather than
    /// an identifier some authorization server issued: the operator named the token after whatever
    /// they handed it to. Defaulting it to <see cref="Name" /> keeps the audit record's
    /// <c>client_id</c> populated with something real, which an earlier draft's constant
    /// <c>static</c> did not.
    /// </para>
    /// <para>
    /// Kept verbatim for the same reason as <see cref="Auth.CallerIdentity.ClientId" />.
    /// </para>
    /// </remarks>
    public string? ClientId { get; init; }
}
