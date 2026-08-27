namespace SshWarden.Authorization;

/// <summary>Turns a job identifier into the two things the gate needs to decide about it.</summary>
/// <remarks>
/// <para>
/// A seam rather than a direct reference to the job store, so the policy - which is the security
/// decision - does not depend on how jobs happen to be kept. It also keeps the direction of the
/// dependency right: the gate asks about a job, the job store does not ask the gate anything.
/// </para>
/// <para>
/// Two values and no more. A gate that could see the command, or the output path, would be a gate
/// that could start making decisions on them, and the classification rule of docs/DESIGN.md §6.5.1 says
/// those are not decidable.
/// </para>
/// </remarks>
public interface IJobLookup
{
    /// <summary>The host and owner of <paramref name="jobId" />, or null if there is no such job.</summary>
    /// <param name="jobId">The identifier the caller sent.</param>
    /// <exception cref="ArgumentNullException"><paramref name="jobId" /> is null.</exception>
    (string Host, string OwnerSubject)? Find(string jobId);
}
