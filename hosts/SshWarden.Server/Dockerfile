# Build and run SshWarden.
#
# Build from the repository root, not from this directory, because the build needs
# Directory.Build.props and Directory.Packages.props above it:
#
#     docker build -f hosts/SshWarden.Server/Dockerfile -t sshwarden .

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /source

# Restore against the project files alone first, so a source-only change does not re-download the
# package graph.
#
# **Every project the host references, transitively, and the list is checked by the image job in
# ci.yml rather than by reading.** A missing one does not fail this step: `dotnet restore` prints
# `Skipping project "…" because it was not found` and reports success, and the failure arrives two
# layers later as NETSDK1004 from `dotnet publish --no-restore` - a missing assets file, which reads
# like a caching problem rather than like a copy list that is one line short.
#
# That is not hypothetical. SshWarden.OAuth was added to the host in step 8 and this list was not,
# so the image could not be built at all until the image job existed to say so. Measured on
# 2026-08-27 by replaying these exact two commands outside a container.
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/SshWarden/SshWarden.csproj src/SshWarden/
COPY src/SshWarden.Mcp/SshWarden.Mcp.csproj src/SshWarden.Mcp/
COPY src/SshWarden.OAuth/SshWarden.OAuth.csproj src/SshWarden.OAuth/
COPY hosts/SshWarden.Server/SshWarden.Server.csproj hosts/SshWarden.Server/
RUN dotnet restore hosts/SshWarden.Server/SshWarden.Server.csproj

COPY src/ src/
COPY hosts/ hosts/
RUN dotnet publish hosts/SshWarden.Server/SshWarden.Server.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# The state directory, created here rather than left to the runtime, and this is load-bearing for
# `deploy/compose.yaml`.
#
# A named volume mounted at a path the image does not have starts owned by root, and the process
# below is not root - so the audit log and the job registry would be unwritable. That is not a
# subtle failure: the audit path is checked for writability before anything is served, deliberately,
# because a choke point that runs commands it cannot record is worse than one that is not running.
# The container would exit 78 on every start. Creating the directory with the right owner first
# means Docker's volume initialisation copies that ownership rather than inventing root's.
#
# Reasoned from how volume initialisation works, not measured: this was written without a daemon.
# What removes the risk is that the shipped compose file works either way, and the README's install
# block does not depend on this line being right.
RUN mkdir -p /var/log/sshwarden && chown $APP_UID:$APP_UID /var/log/sshwarden

# Not root. This process opens SSH connections to production hosts; the blast radius of a container
# escape should not also be a root shell in the container.
USER $APP_UID

# The config file is mounted, never baked in - it holds the credentials, and an image layer is
# readable by anybody who can pull the image.
ENV SSHWARDEN_CONFIG=/etc/sshwarden/sshwarden.toml

# The number the example config's default names. EXPOSE is documentation and publishes nothing.
#
# **The config decides the bind address, and in a container the shipped default is the wrong one.**
# This process binds exactly what `server.listen` says, and that default is `127.0.0.1:8760` - a
# loopback belonging to this container's network namespace, which is not the host's. A published port
# forwards to this container's address rather than to that loopback, so the default answers nothing
# from outside. `deploy/compose.yaml` sets `0.0.0.0:8760` and pins the host half of the mapping to
# loopback instead, which puts the boundary back where the default was trying to put it.
#
# Reasoned rather than measured: the forwarding half was not reproducible without a daemon, and
# Docker's networking documentation does not state it either way (looked, 2026-08-27). This comment
# previously asserted the opposite, that the default was already the reverse-proxy shape, which would
# send a reader to debug a connection that cannot work. Both readings are safe under
# `deploy/compose.yaml`, which is why that file sets the address explicitly rather than relying on
# either.
EXPOSE 8760

ENTRYPOINT ["dotnet", "SshWarden.Server.dll"]
