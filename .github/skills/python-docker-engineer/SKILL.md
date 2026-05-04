---
name: python-docker-engineer
description: "Plan, implement, containerize, and verify Python services with Docker or Docker Compose. Use when building APIs, fixing containerized runtime issues, improving image size/security, or debugging env/config mismatches."
argument-hint: "What are we building or debugging (service, error, expected behavior)?"
user-invocable: true
---

# Python + Docker Engineering Workflow

## Outcome
Produce a reliable Python implementation that runs consistently in local and containerized environments, with repeatable verification and clear operational defaults.

This skill is strict by default: required security and quality gates must pass before work is considered complete.

## When To Use
- New Python service or script that must run in Docker.
- Existing Python project failing in Docker but working locally (or vice versa).
- Build/runtime optimization (smaller image, faster build, safer defaults).
- CI/CD failures tied to packaging, dependencies, or container startup.

## Workflow Mode
- Best-practice mode (default): follow all steps and quality gates.
- Strict mode (required here): treat security, reproducibility, and verification checks as mandatory.

## Inputs To Gather First
- Runtime target: Python version, OS/base image expectations.
- App entrypoint: server command, module path, worker model, exposed port.
- Dependency source: `requirements.txt`, lock files, private indexes.
- Configuration model: env vars, mounted files, secrets, defaults.
- Validation target: tests, health endpoint, smoke command.

## Procedure
1. Define run contract.
- Specify the exact command that starts the app.
- Pin Python major/minor version and required system libraries.
- Decide single-process vs multiprocess behavior and state model.
- Define expected user permissions and filesystem write locations.

2. Normalize Python project behavior.
- Confirm local run command and deterministic dependency install.
- Ensure import paths, package structure, and entrypoint module are correct.
- Add or validate a minimal smoke test or startup check.

3. Build Dockerfile from runtime contract.
- Choose a minimal suitable base image.
- Set stable working directory and copy order for layer caching.
- Install dependencies before source when possible.
- Use explicit startup command (JSON form preferred).
- Add non-root user and least-privilege file permissions.
- Pin base image to a stable version tag and prefer digest pinning when available.

4. Add Compose orchestration only when needed.
- Use Compose for multi-service needs (db, cache, queues).
- Define environment, volume mounts, ports, and service dependencies.
- Add healthchecks for readiness-sensitive dependencies.

5. Verify in container context.
- Build image from clean state.
- Run container and validate startup logs, port binding, and health endpoint.
- Execute smoke tests inside container or against exposed endpoint.
- Validate container handles SIGTERM/SIGINT cleanly and exits predictably.

6. Harden and optimize.
- Remove unnecessary packages and build tools from runtime image.
- Add `.dockerignore` to reduce context size.
- Pin dependencies and avoid floating base tags.
- Scan image for known vulnerabilities.
- Generate or export SBOM if project policy requires supply-chain tracking.

7. Record operations notes.
- Document run/build commands and required env vars.
- Capture known failure signatures and fixes.
- Keep troubleshooting steps near Docker/Compose files.

## Decision Logic
- If app works locally but fails in container: prioritize env var parity, working directory, file paths, and missing OS libs.
- If build is slow: optimize copy order, cache dependency layers, and reduce context size.
- If image is large: remove build-only tools, use slimmer base, and audit dependencies.
- If container exits immediately: inspect entrypoint/cmd format, module path, and startup exceptions.
- If startup is flaky in Compose: add healthchecks and dependency readiness gates.
- If strict gates fail: block release, fix root cause, then rerun full validation.

## Quality Gates (Done Criteria)
- Build is reproducible from a clean environment.
- Container starts without manual patching.
- App responds correctly via defined smoke/health check.
- Dependency versions and Python version are explicit.
- Runtime logs are sufficient to diagnose startup failures.
- Documentation includes exact build/run commands and required config.
- Container runs as non-root unless there is a documented exception.
- Base image and Python package sources are pinned per policy.
- Vulnerability scan is executed and high/critical findings are resolved or formally accepted.
- Secrets are injected at runtime and never baked into image layers.
- Signal handling and graceful shutdown behavior are verified.

## Common Pitfalls Checklist
- Local-only assumptions (relative paths, shell-specific behavior).
- Hidden dependency on dev tools not installed in container.
- Missing `.dockerignore` causing large/slow builds.
- Unpinned dependencies leading to drift.
- Multiple workers with in-memory shared state assumptions.
- Secrets baked into images instead of injected at runtime.
- Root process in runtime container without explicit justification.
- No vulnerability scanning step in CI/CD.

## Example Prompts
- "Use python-docker-engineer to containerize this Python service with a production-safe Dockerfile and Compose file."
- "Use python-docker-engineer to debug why this image builds but crashes at startup."
- "Use python-docker-engineer to reduce image size and improve build caching for this Python service."
