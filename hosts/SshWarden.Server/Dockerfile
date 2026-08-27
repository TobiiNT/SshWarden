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

# Not root. This process opens SSH connections to production hosts; the blast radius of a container
# escape should not also be a root shell in the container.
USER $APP_UID

# The config file is mounted, never baked in - it holds the credentials, and an image layer is
# readable by anybody who can pull the image.
ENV SSHWARDEN_CONFIG=/etc/sshwarden/sshwarden.toml

# Matches the default in the example config. The container has its own network namespace, so
# loopback here means "reachable only through whatever the runtime publishes", which is the
# reverse-proxy shape the README describes.
EXPOSE 8760

ENTRYPOINT ["dotnet", "SshWarden.Server.dll"]
