# Security & Ethics Policy

## What this tool is for

`exposed` is a **defensive privacy tool**. It is designed to be run by a person
against **their own** identity, to discover and reduce their public exposure. It
queries only free, public, no-account sources and stores results locally.

## Acceptable use

- Scanning your own name, emails, usernames, and phone numbers.
- Auditing an identity you are explicitly authorized to assess (e.g. your own
  organization's accounts, with permission).

## Not acceptable

- Using it to profile, stalk, or build dossiers on other people.
- Automating bulk lookups of third parties.

Contributions that shift the tool toward offensive/mass-profiling use will be
declined.

## Handling of personal data

- Your identity lives in `exposed_identity.json`, which is **git-ignored** and never
  leaves your machine.
- Scan output (`*_report.json`) is also git-ignored.
- The tool sends data to a third party only as part of a lookup you requested, and
  stores results only in the local report file you control.

## Reporting a vulnerability

If you find a security issue in the code (e.g. a way it could leak the operator's
data, or a command-injection path), please **do not open a public issue**. Instead
use GitHub's **private vulnerability reporting** (Security → Report a vulnerability)
on this repository. We'll acknowledge within a few days.
