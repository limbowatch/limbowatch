# limbowatch

The library behind [Limbowatch](https://limbo.watch): it tracks security advisories **in limbo**, meaning published by maintainers on GitHub but not yet in GitHub's reviewed Advisory Database or OSV, so scanners that read those databases don't report them.

Most people want the command line instead: `pip install limbowatch-cli`. See the [watcher guide](https://github.com/limbowatch/limbowatch/blob/main/docs/WATCHER.md).

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via the limbo feed (CC BY 4.0). Code: Apache-2.0.
