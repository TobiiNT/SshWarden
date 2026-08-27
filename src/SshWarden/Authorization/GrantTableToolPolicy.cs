using System.Text.Json;

using SshWarden.Auth;

namespace SshWarden.Authorization;

/// <summary>The policy the grant table implements.</summary>
public sealed class GrantTableToolPolicy : ISshWardenToolPolicy
{
    private readonly GrantTable _grants;
    private readonly IJobLookup? _jobs;

    /// <summary>Builds the policy over a grant table.</summary>
    /// <param name="grants">The rules.</param>
    /// <param name="jobs">
    /// How to resolve a job identifier, when this build has jobs. Null when it does not - and a
    /// call naming a job is then refused rather than allowed, because a gate that cannot resolve
    /// the thing it gates on has not decided anything.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="grants" /> is null.</exception>
    public GrantTableToolPolicy(GrantTable grants, IJobLookup? jobs = null)
    {
        ArgumentNullException.ThrowIfNull(grants);

        _grants = grants;
        _jobs = jobs;
    }

    /// <inheritdoc />
    public AuthorizationDecision Allows(CallerIdentity caller, string tool)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(tool);

        return _grants.AuthorizeTool(caller, tool);
    }

    /// <inheritdoc />
    public AuthorizationDecision AllowsArguments(
        CallerIdentity caller,
        string tool,
        IReadOnlyDictionary<string, JsonElement>? arguments)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(tool);

        // A job identifier stands for a host rather than carrying one, so it is resolved first and
        // then decided like any other host - which is what stops a caller reaching another's job
        // through an argument that mentions no machine at all.
        if (ResourceArguments.JobArgumentByTool.TryGetValue(tool, out var jobArgument))
        {
            return AuthorizeJob(caller, tool, arguments, jobArgument);
        }

        // A tool with no gateable argument is decided entirely by Allows, which the call filter has
        // already asked. Answering allow here is not a gap: there is no resource in the arguments
        // for this stage to decide about.
        if (!ResourceArguments.HostArgumentByTool.TryGetValue(tool, out var hostArgument))
        {
            return _grants.AuthorizeTool(caller, tool);
        }

        if (!TryReadString(arguments, hostArgument, out var host))
        {
            // Not "not granted". The gate could not find the argument it gates on, which is a
            // defect in the tool's schema or in this map rather than a statement about the caller's
            // permissions - and calling it a permission refusal would send somebody to edit the
            // grant table over a problem no grant can fix.
            return AuthorizationDecision.Refuse(
                AuthorizationRefusal.HostArgumentMissing,
                $"SshWarden refused tool '{tool}': it names no '{hostArgument}', so there is "
                    + "nothing to authorize it against.");
        }

        if (!ResourceArguments.PathArgumentByTool.TryGetValue(tool, out var pathArgument))
        {
            return _grants.AuthorizeHost(caller, tool, host);
        }

        if (!TryReadString(arguments, pathArgument, out var selector))
        {
            return AuthorizationDecision.Refuse(
                AuthorizationRefusal.PathArgumentMissing,
                $"SshWarden refused tool '{tool}': it names no '{pathArgument}', so there is "
                    + "nothing to authorize it against.");
        }

        if (!ResourceArguments.NamesAPath(selector))
        {
            return _grants.AuthorizeUnit(caller, tool, host, selector);
        }

        if (!PathPattern.TryNormalize(selector, out var normalized, out var problem))
        {
            // Before any rule is consulted, because a rule cannot be checked against a string whose
            // meaning depends on where it is read from.
            return AuthorizationDecision.Refuse(
                AuthorizationRefusal.PathNotUsable,
                $"SshWarden refused tool '{tool}': {problem}");
        }

        return _grants.AuthorizePath(caller, tool, host, normalized);
    }

    private AuthorizationDecision AuthorizeJob(
        CallerIdentity caller,
        string tool,
        IReadOnlyDictionary<string, JsonElement>? arguments,
        string jobArgument)
    {
        if (!TryReadString(arguments, jobArgument, out var jobId))
        {
            return AuthorizationDecision.Refuse(
                AuthorizationRefusal.JobArgumentMissing,
                $"SshWarden refused tool '{tool}': it names no '{jobArgument}', so there is nothing "
                    + "to authorize it against.");
        }

        // No lookup means this build cannot resolve a job, so it cannot decide about one. Refusing
        // is the only answer that is not a guess - a gate that cannot see the resource has not
        // gated it.
        var job = _jobs?.Find(jobId);
        if (job is null)
        {
            return NoSuchJob(tool);
        }

        // Ordinal, and by subject. The comparison that stops one caller reaching another's job -
        // see JobRecord.OwnerSubject for why it is the subject rather than the grant.
        if (!string.Equals(job.Value.OwnerSubject, caller.Subject, StringComparison.Ordinal))
        {
            // Refused as "no such job", so the identifier space is not something worth searching:
            // telling a caller that an identifier exists but is not theirs is telling them it
            // exists. The audit record keeps the real reason, because the operator reading it is
            // not the one being refused.
            return AuthorizationDecision.Refuse(
                AuthorizationRefusal.JobNotOwned,
                NoSuchJobDetail(tool));
        }

        // And still the host rule. Owning a job is not permission to reach the machine it runs on -
        // a rule that stopped covering that host since the job started stops covering the job too.
        return _grants.AuthorizeHost(caller, tool, job.Value.Host);
    }

    private static AuthorizationDecision NoSuchJob(string tool)
        => AuthorizationDecision.Refuse(AuthorizationRefusal.JobNotFound, NoSuchJobDetail(tool));

    private static string NoSuchJobDetail(string tool)
        => $"SshWarden refused tool '{tool}': no such job (rule: "
            + AuthorizationRefusal.JobNotFound + ").";

    private static bool TryReadString(
        IReadOnlyDictionary<string, JsonElement>? arguments,
        string name,
        out string value)
    {
        value = string.Empty;

        if (arguments is null || !arguments.TryGetValue(name, out var element))
        {
            return false;
        }

        // Only a JSON string counts. A number or an object here is not a host name that went
        // through a lenient conversion; it is a call that does not match the schema, and coercing
        // it would mean the gate decides about a value the tool will later reject or read
        // differently.
        if (element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var text = element.GetString();
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        value = text;
        return true;
    }
}
