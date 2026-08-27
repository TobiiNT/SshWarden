using System.Text.Json;

using SshWarden.Auth;

namespace SshWarden.Authorization;

/// <summary>Whether a caller may see a tool, and whether they may call it with these arguments.</summary>
/// <remarks>
/// <para>
/// Two questions, because they have different reach and different answers. docs/DESIGN.md §6.5.5.
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="Allows" /> runs for <c>tools/list</c> <strong>and</strong> <c>tools/call</c>. A
///       refusal there hides the tool. It cannot consider arguments, because a listing has none -
///       and that is the right shape rather than a limitation: whether <c>run</c> is visible does
///       not depend on which host somebody was about to name.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="AllowsArguments" /> runs only for <c>tools/call</c>. It refuses; it cannot
///       hide, for the same reason.
///     </description>
///   </item>
/// </list>
/// <para>
/// Both are wired from one call, deliberately. Filtering the listing without gating the call
/// produces a surface that <em>looks</em> gated: anybody who already knows a tool's name still
/// reaches it.
/// </para>
/// </remarks>
public interface ISshWardenToolPolicy
{
    /// <summary>Whether <paramref name="caller" /> may see and call <paramref name="tool" />.</summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    AuthorizationDecision Allows(CallerIdentity caller, string tool);

    /// <summary>
    /// Whether <paramref name="caller" /> may call <paramref name="tool" /> with
    /// <paramref name="arguments" />.
    /// </summary>
    /// <param name="caller">Who is calling.</param>
    /// <param name="tool">The tool name.</param>
    /// <param name="arguments">
    /// The arguments as they arrived, before binding - so a policy reads them by name, and a
    /// misspelled name here silently removes a gate. That is what the startup check exists for.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="caller" /> or <paramref name="tool" /> is null.</exception>
    AuthorizationDecision AllowsArguments(
        CallerIdentity caller,
        string tool,
        IReadOnlyDictionary<string, JsonElement>? arguments);
}
