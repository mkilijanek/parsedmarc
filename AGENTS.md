# Repository Guidelines

## Project Structure & Module Organization
- Root Docker assets: `Dockerfile`, `Dockerfile.hardened`, and locked variants (`Dockerfile-*.locked`) define image flavors.
- Runtime orchestration: `docker-compose.yml` wires `parsedmarc` with `msgraph-token-refresh`.
- Configuration examples live in `.env.example` and `ini/parsedmarc.ini.example`.
- CI/security automation is in `.github/workflows/` (build checks, release publish, Trivy, Snyk).
- Utility scripts: `build.sh` builds and optionally pushes `ghcr.io/mkilijanek/parsedmarc`.

## Build, Test, and Development Commands
- `docker build -f Dockerfile -t parsedmarc:dev .`
Build local standard image.
- `docker build -f Dockerfile.hardened -t parsedmarc:dev-distroless .`
Build hardened/distroless image.
- `docker compose up -d --build`
Start local stack (token refresher + parsedmarc).
- `./build.sh`
Build release-style image using `PARSEDMARC_VERSION` and OCI metadata.
- `docker compose logs -f parsedmarc msgraph-token-refresh`
Follow startup and token-generation logs.

## Coding Style & Naming Conventions
- Use 2-space indentation in YAML (`docker-compose.yml`, workflow files).
- Shell scripts should stay POSIX `sh` compatible unless Bash is required.
- Environment variables and build args use `UPPER_SNAKE_CASE` (e.g., `PARSEDMARC_VERSION`, `BUILD_DATE`).
- Keep image tags and workflow metadata reproducible (commit-based `SOURCE_DATE_EPOCH`).

## Testing Guidelines
- There is no Python unit-test suite in this repository; validation is container-centric.
- Required pre-merge checks: Docker build workflow succeeds for both `Dockerfile` and `Dockerfile.hardened`.
- Run a local smoke test before PRs: bring up compose stack and confirm `/tokens/.token.json` is created and `parsedmarc` starts.
- Security quality gates are CI-based: Trivy + Snyk workflows on PR/push.

## Commit & Pull Request Guidelines
- Follow conventional prefixes seen in history: `fix: ...`, `chore: ...`, and dependency `Bump ...` commits.
- Keep commits scoped (one concern per commit) and explain impact in imperative mood.
- PRs should include: purpose, changed files/images, local validation commands run, and any secret/config changes.
- Link related issues and include logs/screenshots when behavior or security scan output changes.

## Security & Configuration Tips
- Never commit real secrets. Use `.env` (from `.env.example`) and `secrets/msgraph_client_secret.txt` locally.
- Keep `ini/parsedmarc.ini` in sync with token path `/tokens/.token.json` when using Graph auth.

## Local Environment Notes
- Prefer a local Python `venv` for Python-based tooling and validation commands.
- Use `sudo` only for operations that explicitly require system-level privileges; avoid it for normal repository work.
