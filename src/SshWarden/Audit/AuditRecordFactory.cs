using System.Buffers.Text;
using System.Security.Cryptography;

using SshWarden.Auth;
using SshWarden.Authorization;
using SshWarden.Output;

namespace SshWarden.Audit;

/// <summary>Builds the records the rest of SshWarden writes.</summary>
/// <remarks>
/// A factory rather than five call sites constructing records by hand, because every record has to
/// carry all five identity values and a caller that forgets one leaves a hole nobody notices until
/// the day the log is being read under pressure.
/// </remarks>
public static class AuditRecordFactory
{
    private const string IdPrefix = "sw_rec_";

    /// <summary>A record for a call that was allowed and then did not complete.</summary>
    /// <param name="caller">Who called.</param>
    /// <param name="tool">Which tool.</param>
    /// <param name="startedAt">When the call started.</param>
    /// <param name="host">The host argument, when the call named one.</param>
    /// <param name="error">Why it did not complete. Masked here rather than by the caller.</param>
    /// <param name="allowedBy">The rule that allowed it, when the call got that far.</param>
    /// <param name="sshUser">The account it would have run as.</param>
    /// <param name="selector">The path or unit the caller named, if any.</param>
    /// <param name="jobId">The job, for a job tool.</param>
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    /// <remarks>
    /// The sibling of <see cref="Refusal" />, and the two are different records on purpose: a
    /// refusal is this server deciding, a failure is this server trying and not getting there. An
    /// operator alerts on them separately - a rise in refusals is a permissions question, a rise in
    /// failures is a network or a host question - and one shared "did not work" answers neither.
    /// </remarks>
    public static AuditRecord Failure(
        CallerIdentity caller,
        string tool,
        DateTimeOffset startedAt,
        string? host,
        string error,
        string? allowedBy = null,
        string? sshUser = null,
        string? selector = null,
        string? jobId = null)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(error);

        return new AuditRecord
        {
            Id = NewId(),
            Type = AuditRecordTypes.Command,
            StartedAt = startedAt,
            Subject = caller.Subject,
            ClientId = caller.ClientId,
            GrantId = caller.GrantId,
            TokenId = caller.TokenId,
            Tool = tool,

            // Allowed, because it was: the gate let it through and the work is what failed. Calling
            // it a denial would put a network failure in the column an operator reads as "somebody
            // tried to reach something they should not".
            Decision = AuditDecisions.Allow,
            AllowedBy = allowedBy,
            Host = host,
            SshUser = sshUser,
            Selector = selector,
            JobId = jobId,
            Error = SecretRedactor.Redact(error).Text,
        };
    }

    /// <summary>A record for a refused call.</summary>
    /// <param name="caller">Who called.</param>
    /// <param name="tool">Which tool.</param>
    /// <param name="decision">The refusal.</param>
    /// <param name="startedAt">When the call arrived.</param>
    /// <param name="host">The host named in the arguments, if any was readable.</param>
    /// <param name="selector">The path or unit the caller named, if any.</param>
    /// <param name="resolvedPath">What that path turned out to be on the target, if it got that far.</param>
    /// <exception cref="ArgumentNullException">Any required argument is null.</exception>
    /// <remarks>
    /// A refusal is a record like any other. The line saying an agent went for a production host
    /// and was stopped is the most useful one on the dashboard, and it only exists if refusals are
    /// written.
    /// </remarks>
    public static AuditRecord Refusal(
        CallerIdentity caller,
        string tool,
        AuthorizationDecision decision,
        DateTimeOffset startedAt,
        string? host,
        string? selector = null,
        string? resolvedPath = null)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(decision);

        return new AuditRecord
        {
            Id = NewId(),
            Type = AuditRecordTypes.Decision,
            StartedAt = startedAt,
            Subject = caller.Subject,
            ClientId = caller.ClientId,
            GrantId = caller.GrantId,
            TokenId = caller.TokenId,
            Tool = tool,
            Decision = AuditDecisions.Deny,
            DeniedBy = decision.RefusedBy,
            Host = host,
            Selector = selector,
            ResolvedPath = resolvedPath,
        };
    }

    /// <summary>An identifier for a new record.</summary>
    public static string NewId() => IdPrefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(12));
}
