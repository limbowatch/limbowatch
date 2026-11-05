> **Draft, not sent.** Phase 3 closed on 2026-11-05 without outreach, at the maintainer's choice. Numbers are as of 2026-10-31; refresh them before using this.

Repo: RogoLabs/RBP
Title: A self-refreshing repo list for the ghsa-repos feed?

Hi. `rbp/feeds.py` notes that `feed_data/ghsa_repos.txt` is "NOT SELF-REFRESHING. Discovering a repository that publishes its FIRST advisory is a mining problem and it is not solved here." I think I can help with that.

I run [limbo.watch](https://limbo.watch), a daily tracker of published repository advisories that GitHub hasn't reviewed yet. Its watchlist (about 18,600 repos) refreshes itself every day. It adds:

- every repo named by a CVE that GitHub's CNA publishes (from the cvelistV5 delta log);
- origin repos of reviewed advisories;
- dependency upstreams of popular projects.

Compared with your list (curated 2026-08-26), as of 2026-10-31:

- 1,848 of your 1,871 repos are on our watchlist.
- **3,727 repos with at least one published repository advisory are not on your list.**
- Of the unreviewed advisories we track that cite a CVE we last saw as `RESERVED`, **416 (in 188 repos)** are in repos outside your list.

The list is already published daily at https://limbo.watch/feed/repos.txt, in the same format as yours: one `owner/repo` per line, `#` comments, repo names only. It has no CVE IDs, so it fits your rule that the public branch carries counts, never identifiers. You could pull it in place of, or in addition to, the committed list. If you'd rather keep curating by hand, the same list could be a one-off PR to `ghsa_repos.txt`.

Would either be useful?
