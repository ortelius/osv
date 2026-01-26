# Ortelius v12 OSV Loader
Architecture and Data Flow

> Version 12.0.0

Vulnerabilities from osv.dev
![Release](https://img.shields.io/github/v/release/ortelius/pdvd-osvdev-job?sort=semver)
![license](https://img.shields.io/github/license/ortelius/.github)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/pdvd-osvdev-job/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/pdvd-osvdev-job/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/pdvd-osvdev-job/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/pdvd-osvdev-job/workflows/CodeQL/badge.svg) 
[![OpenSSF-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/pdvd-osvdev-job/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/pdvd-osvdev-job)
![Discord](https://img.shields.io/discord/722468819091849316)


## Purpose

The Ortelius v12 OSV Loader is a Kubernetes-native ingestion job responsible for synchronizing vulnerability intelligence from osv.dev into the Ortelius vulnerability evidence store.

It enables Ortelius to continuously correlate newly disclosed open-source vulnerabilities against packages deployed in live environments, supporting post-deployment vulnerability detection and remediation.

## Why OSV.dev

OSV.dev is the authoritative open-source vulnerability database maintained by Google and the OpenSSF ecosystem. It provides:

- First-party vulnerability disclosures

- Accurate version-range semantics

- Ecosystem-specific package identifiers

- CVE and GHSA alias mapping

- Near real-time vulnerability updates

Ortelius consumes OSV data to ensure vulnerability intelligence remains current even after applications have already been deployed.


              ┌───────────────────────┐
              │        OSV.dev         │
              │  Vulnerability Feeds   │
              └──────────┬────────────┘
                         │
                         ▼
            ┌───────────────────────────┐
            │  pdvd-osvdev-job (Go)     │
            │                           │
            │ • Fetch OSV records       │
            │ • Normalize vulnerability │
            │   metadata                │
            │ • Parse version ranges    │
            │ • Map aliases (CVE/GHSA)  │
            │ • Batch persistence       │
            └──────────┬────────────────┘
                         │
                         ▼
            ┌───────────────────────────┐
            │        ArangoDB            │
            │   Vulnerability Store     │
            │                           │
            │ • OSV vulnerability docs  │
            │ • Package indexes         │
            │ • Ecosystem mapping       │
            │ • Version constraints     │
            └──────────┬────────────────┘
                         │
                         ▼
            ┌───────────────────────────┐
            │        Ortelius            │
            │                           │
            │ • Digital twin inventory  │
            │ • SBOM correlation        │
            │ • Runtime exposure        │
            │ • Remediation workflows   │
            └───────────────────────────┘



---

## Execution Model

The OSV loader is deployed as a **stateless Kubernetes Job or CronJob** using Helm.

Execution sequence:

1. Container starts
2. Configuration loaded from environment variables and secrets
3. OSV vulnerability data is retrieved
4. Records are normalized and indexed
5. Data is written to ArangoDB
6. Job exits successfully

This design supports:

- Safe re-execution
- Horizontal scaling
- Scheduled refresh
- Stateless recovery

---

## Data Ingestion Workflow

### 1. Retrieve Vulnerability Data

The loader retrieves vulnerability entries from osv.dev containing:

- OSV vulnerability identifiers
- Affected ecosystems (npm, Maven, PyPI, Go, etc.)
- Package names
- Introduced and fixed version events
- CVE and GHSA aliases
- Severity metadata
- Published and modified timestamps

---

### 2. Normalize Records

Raw OSV entries are normalized into a structure optimized for runtime correlation:

- Package names normalized per ecosystem
- Version ranges converted into queryable constraints
- Alias mappings preserved for CVE/GHSA lookups
- Metadata standardized for indexing

This enables Ortelius to precisely determine:

- Which deployed components are affected
- Which versions are vulnerable
- Whether remediation is available

---

### 3. Persist to ArangoDB

Normalized records are persisted using:

- Batched inserts and upserts
- Indexes on:
  - ecosystem
  - package name
  - vulnerability ID
  - aliases
  - modified timestamp

This ensures:

- Idempotent execution
- Efficient incremental updates
- High-performance query operations

---

## How Ortelius Uses This Data

Once ingested, OSV vulnerability data becomes part of the Ortelius **software supply chain evidence store**.

Ortelius correlates vulnerabilities against:

- Deployed application inventories
- Runtime SBOMs
- Digital twins of production environments
- Service-to-package dependency graphs

This enables:

- Detection of vulnerabilities after deployment
- Identification of impacted runtime endpoints
- Blast-radius analysis
- Risk prioritization
- Automated remediation workflows

---

## Design Principles

### Post-Deployment Security

The OSV Loader supports Ortelius’ defensive security model by addressing vulnerabilities that emerge after software is running in production.

---

### Idempotent and Safe

- Jobs can be safely re-run
- Vulnerabilities are upserted by ID
- Duplicate ingestion is prevented

---

### Cloud-Native

- Kubernetes-native execution
- Helm-based deployment
- Externalized configuration
- Stateless containers

---

## Recommended Execution Frequency

| Environment | Interval |
|------------|----------|
| Development | Daily |
| Production | Daily or every 6–12 hours |
| Regulated / Mission Systems | Daily |

OSV vulnerability disclosures occur continuously; frequent refresh ensures accurate exposure visibility.

---

## Relationship to Other Ortelius Services

The OSV Loader functions as a foundational data ingestion component within the Ortelius platform:

- Supplies vulnerability intelligence
- Feeds runtime exposure analysis
- Enables AI-driven remediation
- Supports compliance and audit evidence

It does not perform scanning itself; instead, it enables correlation between vulnerability intelligence and deployed software inventories.

---

## Summary

The **Ortelius v12 OSV Loader** provides the vulnerability intelligence backbone for Ortelius’ post-deployment security model by:

- Continuously ingesting OSV.dev disclosures
- Normalizing vulnerability metadata
- Persisting evidence in ArangoDB
- Enabling detection of vulnerabilities affecting live systems

This component is critical to shifting software supply chain security from **prevention-only** toward **continuous detection and response**.

---

## License

Apache License 2.0

---

## Community

- Website: https://ortelius.io  
- GitHub: https://github.com/ortelius  
- Discord: https://discord.gg/ortelius  

---

Maintained by the Ortelius open-source community.
