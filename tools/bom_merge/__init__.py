"""In-memory aggregation and conflict detection for CycloneDX component records.

This package does not introduce a new package identifier. It only consumes the
existing data model of ``cyclonedx-python-lib`` (PURL, CPE, group/name/version,
hashes, bom-ref, evidence, properties) and implements deterministic merge rules
on top of it.
"""
