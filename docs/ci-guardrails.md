# CI Guardrails

These are the release and CI rules that matter most for `sfetch`.

## Shell And Bootstrap Changes

- Validate the exact user entrypoint that changes. If `scripts/install-sfetch.sh` changes, CI must run that script on the real target runner.
- Do not treat `GOOS/GOARCH` build success as proof that bootstrap selection works. Build validation and installer validation cover different failure modes.
- On Windows, test under the same shell the workflow actually uses (`bash`, `pwsh`, or both).

## Hermetic Tests

- Any test that shells out must control its subprocess environment.
- Strip inherited `PATH` and platform-discovery variables before adding mocks.
- Do not rely on local developer machines to surface CI runner behavior. Linux CI may have tools on `PATH` that macOS does not, and Windows runners may report architecture differently depending on shell.

Recommended variables to scrub when testing platform detection:

```text
PATH
RUNNER_ARCH
PROCESSOR_ARCHITECTURE
PROCESSOR_ARCHITEW6432
MOCK_UNAME_S
MOCK_UNAME_M
MOCK_POWERSHELL_OS
GITHUB_TOKEN
GH_TOKEN
SFETCH_GITHUB_TOKEN
```

## GitHub Actions Authentication

- Default policy: no anonymous GitHub API calls in CI.
- Export `GITHUB_TOKEN`, `GH_TOKEN`, and `SFETCH_GITHUB_TOKEN` at workflow or job scope so child processes inherit authenticated access.
- If a step intentionally avoids auth, document why in the workflow.

## Release Validation

Before tagging a release:

1. Run `make prepush`.
2. Confirm the runner matrix covers every supported release platform path that has custom bootstrap logic.
3. Confirm dogfood/install jobs use authenticated GitHub requests.
4. Confirm the release workflow validates the shipped installer path, not only direct binary execution.

After publishing:

1. Run installed-path self-update against the published release.
2. Confirm `--version-extended` reports the release commit.
3. Confirm the GitHub release contains archives, installer, public keys, checksum manifests, and checksum signatures.
