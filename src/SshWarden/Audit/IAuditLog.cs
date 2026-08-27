namespace SshWarden.Audit;

/// <summary>Where audit records go.</summary>
/// <remarks>
/// A seam with one implementation, because the thing behind it is the source of truth for
/// everything else this project produces and a test that asserts on what was recorded should not
/// have to read a file off disk to do it.
/// </remarks>
public interface IAuditLog
{
    /// <summary>Records one line.</summary>
    /// <param name="record">The record.</param>
    /// <exception cref="ArgumentNullException"><paramref name="record" /> is null.</exception>
    void Write(AuditRecord record);
}
