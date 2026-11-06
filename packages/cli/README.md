# limbowatch-cli

`limbowatch scan` checks a project's dependencies against security advisories **in limbo**: published by maintainers on GitHub, but not yet in GitHub's reviewed Advisory Database or OSV, so Dependabot, OSV-Scanner and other scanners that read those databases don't report them yet.

```sh
pip install limbowatch-cli      # needs OSV-Scanner 2.7.0 on PATH
limbowatch scan .
```

It reads lockfiles with OSV-Scanner (offline), matches them against the [limbo feed](https://limbo.watch/feed/), reports what can't be checked instead of dropping it, and can keep one issue per finding up to date in GitLab or Gitea/Forgejo. Outputs: table, JSON, Markdown, SARIF, GitLab Code Quality.

Guide: [docs/WATCHER.md](https://github.com/limbowatch/limbowatch/blob/main/docs/WATCHER.md).

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via the limbo feed (CC BY 4.0). Code: Apache-2.0.
