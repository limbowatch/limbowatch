"""The watcher's inventory: what a project depends on, and what can't be checked (Phase 4).

Two backends: OSV-Scanner over a source tree (`osv_scanner`), or an SBOM (`sbom`). Both report every
dependency they can't check as an `UnresolvedDependency` with a reason; nothing is dropped.
"""
