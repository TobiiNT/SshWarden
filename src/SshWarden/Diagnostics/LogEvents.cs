namespace SshWarden.Diagnostics;

/// <summary>
/// Which event ids belong to which assembly, and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// <strong>One place, because the alternative was five numbers chosen by whoever was typing.</strong>
/// The first version of this project's logging had ids 1, 2, 10, 100 and 101 declared inside three
/// unrelated classes. Nothing said which numbers were taken, so adding a message meant reading three
/// files and guessing - and two messages sharing an id is silent: nothing fails, and a dashboard
/// keyed on the id starts counting two different things as one.
/// </para>
/// <para>
/// <strong>A range per assembly rather than a number per event.</strong> An event id is a
/// deployment's query key, so it has to be stable, but a central list of every individual event
/// becomes a merge conflict on every branch that logs anything. A range is stable, gives each
/// assembly room, and makes "which component said this" answerable from the number alone - which is
/// what an operator has in front of them at 3am when the message text has been truncated by
/// whatever is shipping it.
/// </para>
/// <para>
/// <strong>The ids were renumbered when this landed, and that was free exactly once.</strong>
/// Nothing outside this repository consumes them yet: the queryable artefact of this project is the
/// audit record, not the log event id, and no dashboard exists. Renumbering after somebody builds
/// one is a different question and the answer is no, which is the reason to have done it now.
/// </para>
/// <para>
/// <c>LogEventRuleTests</c> holds all of this: every declared id is inside its assembly's range,
/// no two share an id, and every one carries an <c>EventName</c>.
/// </para>
/// </remarks>
public static class LogEvents
{
    /// <summary>Where <c>SshWarden</c>'s own ids start.</summary>
    /// <remarks>
    /// The SSH layer, the change sweeper, the job store - everything that runs without a request
    /// around it, and therefore everything whose failures nobody is waiting on an answer for.
    /// </remarks>
    public const int Core = 1000;

    /// <summary>Where <c>SshWarden.Mcp</c>'s ids start.</summary>
    /// <remarks>The request path: authentication, the tool gate, the endpoints.</remarks>
    public const int Mcp = 2000;

    /// <summary>Where <c>SshWarden.OAuth</c>'s ids start.</summary>
    /// <remarks>
    /// Reserved rather than used. That assembly refuses at startup instead of logging, which is
    /// louder, and the range exists so the day it does log the number is not another choice
    /// somebody makes alone - which is this file's whole argument.
    /// </remarks>
    public const int OAuth = 5000;

    /// <summary>Where the server host's ids start.</summary>
    /// <remarks>Startup and shutdown: what a process says before it serves anything.</remarks>
    public const int Server = 4000;

    /// <summary>How many ids each range holds.</summary>
    /// <remarks>
    /// A thousand, which is more than any of these will use and small enough that the first digit
    /// still names the component. Both halves matter: a range too tight is a renumbering later, and
    /// this file exists because renumbering later is the thing to avoid.
    /// </remarks>
    public const int RangeSize = 1000;
}
