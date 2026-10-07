# Python SDK releases

This repository releases `agenthooksprotocol` to public PyPI independently of the
other SDKs. Release Please maintains a release PR from Conventional Commits on
`main`, updating the changelog, `pyproject.toml`, the package version in `uv.lock`,
and `.release-please-manifest.json`.

## One-time setup

1. Use the existing **Agent Hooks Protocol Bot** GitHub App. Install it on this
   repository with **Contents: read/write** and **Pull requests: read/write**.
   Set Actions variable **`RELEASE_APP_ID`** to its App ID and Actions secret
   **`RELEASE_APP_PRIVATE_KEY`** to a PEM private key generated in its settings.
   Organization-level values may be shared with just the four SDK repositories.
   The workflow mints a short-lived installation token scoped to this repository
   and those two permissions; it is revoked when the job ends. Release PRs,
   tags, and GitHub releases use the bot identity and trigger normal PR CI.
   No personal access token is needed. Keep branch protection enabled.
2. Create the GitHub environment **`release`**. Configure required reviewers if
   desired and allow deployments from **`main`** (the workflow runs on main even
   though checkout uses the released commit).
3. For a new PyPI project, add an account-level **pending publisher** with
   project name **`agenthooksprotocol`** and these exact GitHub values:

   | Field | Value |
   | --- | --- |
   | Owner | `agenthooksprotocol` |
   | Repository | `python-sdk` |
   | Workflow filename | `release.yml` |
   | Environment | `release` |

   No PyPI API token or password is needed. The first successful trusted upload
   creates the project. Pending publishers do **not** reserve names and cannot
   claim an already registered project. If the project already exists, an owner
   must instead add the same trusted publisher in its **Publishing** settings.
   The local package version does not establish whether a PyPI project exists.

## Lifecycle

- Every push to `main` calls the existing CI workflow. Only after CI succeeds does
  Release Please create/update a release PR or create a GitHub release for a
  merged release PR. Existing push/PR CI remains unchanged.
- Review and merge the release PR to release. The manifest starts at `0.0.0`,
  the sentinel for no previous release. `initial-version: 0.1.0` selects only
  the first release; subsequent releases use Conventional Commits. No manual
  configuration removal is needed.
- When Release Please reports a created release, the same workflow checks out
  its exact released SHA, builds wheel and sdist with `python -m build`, and
  publishes through the `release` environment using PyPI trusted publishing.
  Only the publish job receives OIDC permission. There are no installation
  smoke tests, registry probes, or post-publish verification jobs.
- If publishing fails, inspect the failed job and correct the setup before
  rerunning **failed jobs** in the original run (preserving successful Release
  Please outputs). Do not rerun all jobs to recreate a release or try to replace
  an existing PyPI version; PyPI files are immutable.

Official setup references:
[existing project publishers](https://docs.pypi.org/trusted-publishers/adding-a-publisher/),
[pending publisher bootstrap](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/),
and [publishing action](https://github.com/pypa/gh-action-pypi-publish).
