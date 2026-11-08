# Limbowatch CI/CD component

Checks your dependencies against security advisories **in limbo**: published by maintainers on GitHub, but not yet in GitHub's reviewed Advisory Database or OSV. Until they're reviewed, Dependency Scanning, OSV-Scanner, Trivy and Dependabot don't report them, often for weeks.

- **Merge requests, every tier:** each finding on its lockfile line (Code Quality), one failed test per finding at or above `fail_on` (test summary), and a link to the full report.
- **GitLab Ultimate:** findings in the Security tab, the vulnerability report and the merge request security widget (`security_report: true`).
- **Job log:** a table per lockfile, the upgrade that clears each package, and why the job passed or failed.
- **Issues (optional):** one confidential issue per advisory and package, updated when a CVE is assigned or the advisory reaches the scanners, and closed once you've upgraded.
- **Private by design:** OSV-Scanner reads your lockfiles inside the job, and the limbo feed is downloaded whole. Nothing about your project is sent to limbo.watch.

## Components

### `limbowatch`

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0-alpha.4
```

The job fails when a finding is at or above `fail_on` (default `low`). Exit codes: 0 passed, 1 findings, 2 the scan couldn't run. The inputs, with their defaults, are listed on this component's CI/CD Catalog page.

**Merge requests and the default branch only**, failing on high and critical:

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0-alpha.4
    inputs:
      fail_on: high
      rules:
        - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

**Report without blocking:** `allow_failure: true` turns findings into a warning. A scan that couldn't run still fails, so a broken setup doesn't pass silently.

**A weekly schedule with issues.** Advisories are published after you merge, and review takes weeks, so a scheduled pipeline finds what's new. Add a pipeline schedule, then:

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0-alpha.4
    inputs:
      issues: true   # needs LIMBOWATCH_ISSUES_TOKEN, see below
```

**GitLab Ultimate:**

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0-alpha.4
    inputs:
      security_report: true
```

GitLab reads security reports only from jobs that succeed. With `security_report: true`, the `limbowatch` job passes and a second job, `limbowatch-gate`, applies `fail_on`. Findings with a CVE are listed as dependency scanning, the rest as SAST.

**Two projects in one repository:** include the component once per directory, each with its own `job_name`:

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0-alpha.4
    inputs: { job_name: limbowatch-api, path: services/api }
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0-alpha.4
    inputs: { job_name: limbowatch-web, path: services/web }
```

**Anything else:** define the job again to override any keyword, for example the runner:

```yaml
limbowatch:
  tags: [my-runner]
```

## Variables

| Variable | |
|---|---|
| `LIMBOWATCH_GITHUB_TOKEN` | Masked. Any GitHub token that can read public repositories. The job polls the source repos the live tracker doesn't watch, and GitHub allows 60 requests an hour without a token. Repos it can't poll are reported as checked by name only, never skipped. |
| `LIMBOWATCH_ISSUES_TOKEN` | Masked and protected, for `issues: true`. A project access token with `api` scope and at least the Reporter role. Project access tokens need Premium or Ultimate on gitlab.com; on Free, use a personal access token of a bot account added to the project. Merge request pipelines never open issues. |

## The image

The job runs `registry.gitlab.com/limbowatch/limbowatch-component`, pinned by digest in each release. It's a copy of `ghcr.io/limbowatch/limbowatch` with the same digest, built from the Limbowatch source with Limbowatch and OSV-Scanner installed and nothing installed at run time. GitHub Actions builds it for amd64 and arm64, with an SBOM and build provenance. To check where an image came from:

```sh
gh attestation verify oci://ghcr.io/limbowatch/limbowatch@sha256:<digest> --owner limbowatch
```

If your runners can only pull from your own registry, copy the image there with the same digest and set the `image` input.

## Versions

Releases follow semantic versioning, and each one pins a Limbowatch release. Pin a release like `0.1.0-alpha.4`. Use `~latest` only if you want every new version as soon as it's out. This component is an **alpha**: inputs and reports may still change before 0.1.0.

## Contribute

This project is published from [`integrations/gitlab/`](https://github.com/limbowatch/limbowatch/tree/main/integrations/gitlab) in the Limbowatch repository on GitHub. Issues and pull requests go there. The project's own pipeline runs the component against `tests/go-sample` on amd64 and arm64, in both modes.

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via limbo.watch.
