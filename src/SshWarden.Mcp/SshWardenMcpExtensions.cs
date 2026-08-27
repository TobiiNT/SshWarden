using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection.Extensions;

using ModelContextProtocol.Server;

using SshWarden.Audit;
using SshWarden.Auth;
using SshWarden.Authorization;
using SshWarden.Changes;
using SshWarden.Jobs;
using SshWarden.Configuration;
using SshWarden.Mcp.Tools;
using SshWarden.Metrics;
using SshWarden.Ssh;

namespace SshWarden.Mcp;

/// <summary>Wires SshWarden into an ASP.NET Core application.</summary>
public static class SshWardenMcpExtensions
{
    /// <summary>
    /// Registers the authenticator the configuration selects, and the MCP server behind it.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The loaded configuration.</param>
    /// <returns>The MCP server builder, so tools can be added to it.</returns>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    /// <exception cref="NotSupportedException">
    /// The configured authentication mode has no authenticator in this build.
    /// </exception>
    /// <remarks>
    /// <para>
    /// The authenticator is registered with <c>TryAdd</c>, so a registration made <strong>before</strong>
    /// this call wins and one made after it silently does nothing. That is the same contract Boltway
    /// uses for its own seams, and the ordering is part of it rather than an implementation detail:
    /// a deployment replacing the authenticator has to know which side of this call to stand on, and
    /// the wrong side fails by doing nothing at all.
    /// </para>
    /// </remarks>
    public static IMcpServerBuilder AddSshWarden(
        this IServiceCollection services,
        SshWardenConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton(configuration);
        services.TryAddScoped<CallerContext>();

        // The 401 challenge carries the scheme and nothing else unless a mode filled this in
        // first. Static-token mode has no metadata document to point at and no scope vocabulary to
        // name, and inventing either would advertise a capability that is not there; OAuth mode
        // registers a filled one before this call, like every other seam here.
        services.TryAddSingleton(BearerChallengeParameters.None);

        switch (configuration.Auth.Mode)
        {
            case AuthModes.StaticToken:
                services.TryAddSingleton<ISshWardenAuthenticator>(
                    _ => new StaticTokenAuthenticator(configuration.Auth.StaticTokens));
                break;

            case AuthModes.OAuth:
                // Not registered here, and that absence is the seam working: an implementation lives
                // in its own assembly, which a deployment references on purpose, so a static-token
                // install is not made to carry an authorization server's client libraries behind
                // this package.
                //
                // So it has to have been registered already, before this call, like every other seam
                // here. Checked rather than assumed, because the alternative is a process that
                // starts, serves the MCP endpoint, and resolves an authenticator that is not there
                // only when the first caller arrives.
                //
                // The message names both shipped adapters and neither exclusively. SshWarden works
                // with any authorization server that issues JWT access tokens; naming one vendor
                // here would answer "does it work with mine?" with "no", in the one place somebody
                // asking that question is looking.
                if (!services.Any(service => service.ServiceType == typeof(ISshWardenAuthenticator)))
                {
                    throw new InvalidOperationException(
                        $"auth.mode is '{AuthModes.OAuth}' and no {nameof(ISshWardenAuthenticator)} "
                            + "is registered. Reference SshWarden.OAuth and call "
                            + "AddSshWardenOAuth(configuration) before AddSshWarden - that works "
                            + "with any authorization server issuing JWT access tokens. "
                            + "SshWarden.Boltway is the same seam filled by Boltway's own reader, "
                            + $"and so is anything you implement. Or switch to auth.mode "
                            + $"'{AuthModes.StaticToken}'.");
                }

                break;

            default:
                // Unreachable through the config loader, which refuses an unsupported mode with a
                // message naming what this build does support. Kept as a throw rather than a silent
                // fallthrough because the alternative - reaching the end of this switch with no
                // authenticator registered - is a process that starts and serves the MCP endpoint
                // with nothing in front of it.
                throw new NotSupportedException(
                    $"No authenticator is registered for auth.mode '{configuration.Auth.Mode}'. "
                        + "Supported: " + string.Join(", ", AuthModes.All) + ".");
        }

        services.TryAddSingleton(new GrantTable(configuration.Grants));
        // The store is a singleton because it holds the registry file open, and the policy takes it
        // as a lookup rather than as a store: the gate asks about a job, it does not manage one.
        // The logger is passed rather than left to the default, because the default is silence: a
        // registry line that could not be replayed is a job this process will answer "no such job"
        // for while it is still running on the target.
        services.TryAddSingleton(provider => new JobStore(
            configuration.Jobs.Registry,
            provider.GetService<ILogger<JobStore>>()));
        services.TryAddSingleton<IJobLookup>(provider => provider.GetRequiredService<JobStore>());
        services.TryAddSingleton(configuration.Jobs);

        services.TryAddSingleton<ISshWardenToolPolicy>(provider => new GrantTableToolPolicy(
            provider.GetRequiredService<GrantTable>(),
            provider.GetRequiredService<IJobLookup>()));

        // A singleton because it holds the file open. Opening per write would move the failure from
        // startup - where the config loader already proved the path is writable - to the moment a
        // command has just run on somebody's production host and the record of it is what is at
        // stake.
        services.TryAddSingleton(new HostRegistry(configuration.Hosts));

        services.TryAddSingleton(configuration.Metrics);
        services.TryAddSingleton<MetricsCollector>();
        services.TryAddSingleton(provider => new SshWardenMetrics(
            provider.GetRequiredService<HostRegistry>(),

            // Resolved lazily and tolerantly: a deployment with no [ssh] table has no pool, and the
            // gauge for it is then zero rather than a startup failure. An observable instrument
            // whose callback throws is one that takes the whole scrape down with it.
            () => provider.GetService<SshConnectionPool>()?.LiveConnections().Count ?? 0));

        // Decorated rather than replaced, and registered as the IAuditLog everything resolves - so
        // there is no second place a record could be written without being counted. TryAdd still
        // applies to the inner sink: a deployment that registered its own IAuditLog before this call
        // keeps it, and gets it wrapped.
        services.TryAddSingleton<JsonlAuditLog>(_ => new JsonlAuditLog(configuration.Audit.Path));
        services.TryAddSingleton<IAuditLog>(provider => new MeteredAuditLog(
            provider.GetRequiredService<JsonlAuditLog>(),
            provider.GetRequiredService<SshWardenMetrics>()));
        services.TryAddSingleton(configuration.Output);

        // The SSH layer only exists when there is somewhere to reach. A deployment mid-setup with no
        // [[host]] block still starts and still authenticates - and every tool call is refused by
        // the grant table long before anything would look for a connection.
        if (configuration.Ssh is { } ssh)
        {
            services.TryAddSingleton(ssh);
            services.TryAddSingleton(_ => new SshConnectionPool(ssh));
            services.TryAddSingleton(provider =>
                new SshCommandRunner(provider.GetRequiredService<SshConnectionPool>()));

            // The sweeper starts on construction, so it is resolved at startup rather than left to
            // the first tool call - a change detector that only begins once somebody asks about
            // changes has nothing to tell them.
            services.TryAddSingleton(provider => new ChangeSweeper(
                provider.GetRequiredService<SshCommandRunner>(),
                provider.GetRequiredService<HostRegistry>(),
                provider.GetRequiredService<ChangeTimeline>(),
                configuration.Watch,
                provider.GetRequiredService<SweepProblems>()));
        }

        services.TryAddSingleton(configuration.Watch);
        // Resolved through the container rather than with `new`, so it gets the logger: a sweep
        // that has been failing since Tuesday said nothing at all until this was wired.
        services.TryAddSingleton(provider => new SweepProblems(provider.GetService<ILogger<SweepProblems>>()));
        services.TryAddSingleton(
            new ChangeTimeline(TimeSpan.FromMinutes(configuration.Watch.RetentionMinutes)));
        services.TryAddSingleton(
            new CommandOverlap(TimeSpan.FromMinutes(configuration.Watch.RetentionMinutes)));
        services.TryAddSingleton(provider => new ChangeAttribution(
            provider.GetRequiredService<ChangeTimeline>(),
            provider.GetRequiredService<CommandOverlap>()));

        var mcp = services
            .AddMcpServer()

            // Streamable HTTP. Stdio is not offered: docs/DESIGN.md §2 exists because the client cannot
            // reach the machine, so a transport that requires a local process solves nothing here.
            .WithHttpTransport()

            // Both filters, from one call. See SshWardenToolGate for why they are not separable.
            .WithSshWardenToolPolicy();

        // Registered only when there is an SSH layer behind them. A tool that appears in a listing
        // and then answers "this deployment has no hosts" is a capability advertised with nothing
        // behind it, and a client believes a listing.
        if (configuration.Ssh is not null)
        {
            // The generic overload, and that is measured rather than stylistic. **Measured
            // 2026-08-26 against ModelContextProtocol 2.2.0:** registering the same type through
            // `WithTools(new[] { typeof(RunTool) })` - the IEnumerable<Type> overload - compiles,
            // runs, throws nothing, and leaves **zero** McpServerTool services registered, so
            // `tools/list` answers "method not available" and the server has no tools at all.
            // `WithTools<RunTool>()` registers one. Whatever the reason inside the SDK, the two
            // forms are not interchangeable here.
            //
            // That failure is silent from this side, which is why the startup check below now also
            // asserts the tools it expects are actually there rather than only checking the ones
            // that happen to be.
            _ = mcp.WithTools<Tools.RunTool>();
            _ = mcp.WithTools<Tools.ReadTools>();
            _ = mcp.WithTools<Tools.ChangesTool>();
            _ = mcp.WithTools<Tools.JobTools>();
        }

        return mcp;
    }

    /// <summary>
    /// Requires an authenticated caller for everything mapped after this call.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The same builder.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="app" /> is null.</exception>
    /// <remarks>
    /// <para>
    /// Goes in front of <strong>everything</strong>, not just the MCP path, and takes no list of
    /// exempt paths. An endpoint opts out by carrying <see cref="AllowUnauthenticated" />, at the
    /// place it is mapped - so a route added later is authenticated by default, and the exceptions
    /// are visible where somebody would look for them.
    /// </para>
    /// <para>
    /// Call it after <c>UseRouting</c>: the opt-out is endpoint metadata, and before routing there
    /// is no endpoint to read it from.
    /// </para>
    /// </remarks>
    public static IApplicationBuilder UseSshWardenAuthentication(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<SshWardenAuthenticationMiddleware>();
    }

    /// <summary>Maps the MCP endpoint at the configured path, behind authentication.</summary>
    /// <param name="app">The endpoint route builder.</param>
    /// <param name="configuration">The loaded configuration.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    /// <remarks>
    /// <para>
    /// <strong>No scope requirement is declared on this route, and none ever should be.</strong> An
    /// MCP server carries every tool through one endpoint, so a scope required here is the
    /// intersection of what all the tools need - which enforces the widest scope on the narrowest
    /// operation and gates nothing useful. Worse, in the OAuth deployment of step 8, the framework
    /// fills the 401 challenge's scope parameter from exactly that declaration, and MCP clients read
    /// the challenge before they read any metadata document: naming one scope there instructs every
    /// client to ask for only that one. docs/DESIGN.md §6.5.0 records what that cost when it happened.
    /// </para>
    /// <para>
    /// Per-tool authorization arrives at step 2, in an MCP request filter, which is where the
    /// question can actually be asked.
    /// </para>
    /// </remarks>
    public static void MapSshWarden(
        this IEndpointRouteBuilder app,
        SshWardenConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(configuration);

        // Before the route exists, not after. The gate reads arguments by name out of raw JSON, so a
        // name that does not match a tool's schema is a boundary that silently is not there - and
        // the only moment both halves are visible is here, with the tools registered and the policy
        // map beside them.
        // The pool reads the private key in its constructor, and this is what makes that happen at
        // startup rather than at the first tool call. Its own comment always said a deleted or
        // unusable key "should fail loudly here rather than at the first command" - and the lazy
        // registration made "here" *be* the first command.
        //
        // Measured against a running server on 2026-08-26, with a key the loader accepted (present,
        // 0600) and SSH.NET could not parse: the call authenticated, passed the grant table, and
        // then died inside dependency injection *before* the tool method ran - so the record the run
        // tool writes in a finally never got written. A call that reached the SSH layer left nothing
        // in the audit log at all, which is the one hole this project exists to close, and the
        // caller was told "An error occurred invoking 'run'".
        //
        // The earlier reading was that a deployment which watches nothing should not need a working
        // key before it can serve a tool listing. It is the wrong trade: a process serving a tool
        // listing while every call it lists is guaranteed to fail is worse than one that refuses to
        // start and names the file.
        if (configuration.Ssh is not null)
        {
            _ = app.ServiceProvider.GetRequiredService<SshConnectionPool>();
        }

        // Resolved here so the sweeper is running before the endpoint answers anything, rather than
        // starting the first time a tool happens to need it.
        if (configuration.Ssh is not null && configuration.Watch.Paths.Count > 0)
        {
            _ = app.ServiceProvider.GetRequiredService<ChangeSweeper>();
        }

        if (configuration.Metrics.Enabled)
        {
            // Both resolved here rather than left to the first scrape, and the order is the point:
            // System.Diagnostics.Metrics delivers a measurement to whoever is listening at the
            // moment it is taken and keeps nothing, so a listener constructed by the first request
            // to /metrics has missed everything that happened before it. The symptom is a scrape
            // that answers with instrument headers and no numbers, which reads as "nothing has
            // happened yet" rather than as "nobody was listening".
            _ = app.ServiceProvider.GetRequiredService<MetricsCollector>();
            _ = app.ServiceProvider.GetRequiredService<SshWardenMetrics>();
        }

        ToolPolicyCoverage.Verify(
            app.ServiceProvider.GetServices<McpServerTool>(),
            expectTools: configuration.Ssh is not null);

        app.MapMcp(configuration.Server.McpPath);

        if (configuration.Metrics.Enabled)
        {
            // Authenticated, and not marked otherwise. The `host` label carries the names of this
            // deployment's production machines, which is the same information the scope design goes
            // out of its way never to publish - so a scraper needs a token like everything else.
            // The token it should be given is one with no grants at all: the numbers are aggregate
            // and reading them needs no reach, and a scraper holding a token that can run commands
            // is a credential sitting in a config file for the sake of a counter.
            app.MapGet(configuration.Metrics.Path, (MetricsCollector collector) =>
                Results.Text(
                    PrometheusText.Write(collector.Snapshot()),
                    PrometheusText.ContentType));
        }
    }

    /// <summary>
    /// Maps an unauthenticated liveness endpoint.
    /// </summary>
    /// <param name="app">The endpoint route builder.</param>
    /// <param name="path">The path to map. Defaults to <c>/health</c>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="app" /> is null.</exception>
    /// <remarks>
    /// <para>
    /// Deliberately unauthenticated and deliberately empty of detail: it answers whether the process
    /// is up, which is what a reverse proxy and a container runtime need, and nothing about what it
    /// is configured to reach. A health endpoint that lists hosts or tokens is a way to enumerate a
    /// deployment without a credential.
    /// </para>
    /// <para>
    /// It also earns its place for a reason a test suite cannot cover: a dependency whose published
    /// package depends on a version of a transitive package missing a member the compiled code
    /// calls restores, compiles and builds an image, then throws out of host startup into a restart
    /// loop. Starting the process and asking it this question is what catches that; a green test run
    /// does not.
    /// </para>
    /// </remarks>
    public static void MapSshWardenHealth(this IEndpointRouteBuilder app, string path = "/health")
    {
        ArgumentNullException.ThrowIfNull(app);

        app.MapGet(path, () => Results.Json(new { ok = true, server = "sshwarden" }))
            .WithMetadata(AllowUnauthenticated.Instance)

            // The framework's marker as well as this project's, and both are needed. The first is
            // what SshWarden's own middleware reads; this is what any other gate in the pipeline
            // reads, and in OAuth mode there is one - Boltway's, which protects every routed
            // endpoint by default. Without this the liveness probe answered 401, which is a health
            // check that reports the process is unwell whenever authentication is working.
            .AllowAnonymous();
    }
}
