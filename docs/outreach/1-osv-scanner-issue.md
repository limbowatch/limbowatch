> **Draft, not sent.** Phase 3 closed on 2026-11-05 without outreach, at the maintainer's choice. Numbers are as of 2026-10-31; refresh them before using this.

Repo: google/osv-scanner
Title: Feature request: configurable host for offline database downloads

### Summary

OSV-SCALIBR's `osvlocal` enricher has had a configurable `RemoteHost` since google/osv-scalibr@5e3ca53 (#1608 there). OSV-Scanner still hard-codes it to `https://osv-vulnerabilities.storage.googleapis.com`, in `pkg/osvscanner/scan.go` and `cmd/osv-scanner/fix/command.go`.

Could OSV-Scanner expose it, for example as `--local-db-host` and `OSV_SCANNER_LOCAL_DB_HOST`? The default would stay the same.

In #2198, "download the .zip files from a custom url" was listed as one way to support a custom database. That request was closed because the reporter wanted a MySQL backend instead. This is the zip-URL option.

### Use cases

- **Mirrors and air-gapped networks.** Serve a copy of the bucket from an internal host. Today the only way is to copy zips into the cache directory by hand.
- **Supplementary databases in OSV format.** I run [limbo.watch](https://limbo.watch). It publishes security advisories that maintainers have published on GitHub, but that GitHub hasn't reviewed into its Advisory Database yet, so OSV doesn't have them. Today that's about 8,000 in ecosystems GitHub reviews, a median of 57 days after publication. They're at `https://limbo.watch/osv/<Ecosystem>/all.zip`, in the same layout as your bucket. Each zip is sent with `X-Goog-Hash: crc32c=…`, so the cache check works. Every OSV ecosystem has a file, empty where we have nothing, because an ecosystem missing in offline mode fails the whole scan.

### What works today, and what doesn't

With v2.7.0, a user can already scan against those zips:

```sh
curl -O https://limbo.watch/osv/limbo-db.zip && unzip -q limbo-db.zip -d limbo-db
osv-scanner scan source --offline-vulnerabilities --local-db-path limbo-db -r .
```

But that's a manual download each time. It doesn't refresh, and it scans against the supplementary data instead of OSV's.

### Tested

I patched v2.7.0 to read `RemoteHost` from an environment variable (one line in `pkg/osvscanner/scan.go`), then ran it twice with `--offline-vulnerabilities --download-offline-databases` against `https://limbo.watch/osv`:

- On the first run, it downloaded the npm and PyPI zips.
- On the second run, it sent only `HEAD` requests, matched the CRC-32C and reused the cache.

Both runs reported the same 77 findings for `frappe==15.0.0` and `@vendure/core@3.0.0`. None of those advisories are on OSV.dev yet, e.g. `GHSA-22x4-937q-5fr5` returns 404.

### Possible follow-up

A single host replaces OSV's data. To use a supplementary database alongside OSV, the scanner could take a list of extra hosts and match against each. SCALIBR already de-duplicates findings from several matchers (`dedupPackageVulns`). I'd be glad to discuss how that should look, but the single host is useful on its own.

If you're open to the first part, I can send a PR with tests.
