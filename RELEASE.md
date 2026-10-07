# Python SDK releases

This repository releases `agenthooksprotocol` to public PyPI independently of the
other SDKs. Release Please maintains a release PR from Conventional Commits on
`main`, updating the changelog, `pyproject.toml`, the package version in `uv.lock`,
and `.release-please-manifest.json`.

## One-time setup

1. Add the repository secret `RELEASE_PLEASE_TOKEN`: a fine-grained GitHub personal
   access token scoped to `agenthooksprotocol/python-sdk`, with **Contents: Read
   and write** and **Pull requests: Read and write**. Obtain organization approval
   if required. Unlike `GITHUB_TOKEN`, this token allows the bot's PRs to trigger
   the existing CI. Permit GitHub Actions and release PRs in repository settings.
2. Create the GitHub environment **`release`**. Configure required reviewers if
   desired and allow deployments from **`main`** (the workflow runs on main even
   though checkout uses the released commit).
3. As an owner of the existing PyPI project **`agenthooksprotocol`**, open its
   **Publishing** settings and add a GitHub trusted publisher with these exact
   values:

   | Field | Value |
   | --- | --- |
   | Owner | `agenthooksprotocol` |
   | Repository | `python-sdk` |
   | Workflow filename | `release.yml` |
   | Environment | `release` |

   No PyPI API token or password is needed. The project already has version
   `0.0.0`, so configure its existing publisher settings, not a pending publisher.
   For a genuinely new project, PyPI supports an account-level **pending
   publisher** with the project name and the same workflow identity; the first
   successful trusted upload creates the project. Pending publishers do **not**
   reserve names and cannot claim an already registered project.

## Lifecycle

- Every push to `main` calls the existing CI workflow. Only after CI succeeds does
  Release Please create/update a release PR or create a GitHub release for a
  merged release PR. Existing push/PR CI remains unchanged.
- Review and merge the release PR to release. The initial manifest and package
  version remain `0.0.0`; `release-as: 0.1.0` explicitly selects the first release.
  **Remove `release-as` from `release-please-config.json` in that first release PR
  before merging it**, leaving the generated `0.1.0` version changes intact, so
  subsequent releases use Conventional Commits instead of a fixed version.
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
