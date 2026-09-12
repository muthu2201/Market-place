# 0008. Crypto-shredding reconciles erasure with retention

Status: Accepted
Date: 2026-09-11

## Context

Two laws give directly contradictory instructions about the same row.

The Digital Personal Data Protection Act, 2023 (and GDPR Article 17 for EU
buyers) gives a person the right to have their personal data erased. The
Income-tax Act and the CGST Act require books of account, tax invoices and
supporting records to be retained for six to eight years, and a tax invoice
carries the recipient's name and, where registered, their address and GSTIN.

Delete the row and the statutory record is destroyed. Keep the row and the
erasure request is refused. Both are violations, and "we'll handle it manually"
is how a startup discovers at scale that it cannot.

## Decision

Personal data is never stored in the clear. Each data subject has a data
encryption key (DEK); every personal field is sealed with AES-256-GCM under that
DEK, with the subject ID and the field name bound in as additional authenticated
data. The DEK itself is stored wrapped under a deployment key-encryption key
(KEK) in `subject_keys`.

**Erasure destroys the DEK.** The ciphertext stays exactly where it is, in every
backup and every archived record, and becomes permanently unreadable. The
financial record survives — amounts, dates, tax computations, invoice numbers,
the gapless series — because none of those are personal data. What was readable
becomes a tombstone.

Binding the field name into the AAD means a ciphertext cannot be moved from one
column to another, and binding the subject ID means it cannot be moved from one
person to another, even by someone with write access to the database.

## Lookup without plaintext

An encrypted e-mail address cannot be searched, but login needs an exact-match
lookup. A **blind index** solves it: `HMAC-SHA256` under a pepper derived from
the KEK, stored alongside the ciphertext and indexed uniquely.

Normalisation before hashing is deliberately conservative. The domain is
lowercased, because DNS is case-insensitive. The local part is **not** — RFC 5321
makes it case-sensitive, and folding it would silently merge two different
mailboxes into one account. No plus-address stripping, for the same reason: the
platform does not get to decide that two addresses a mail server treats as
distinct are the same person.

A blind index leaks equality, and only equality: an attacker with the database
learns that two rows hold the same address, never which address, and cannot
build a rainbow table without the pepper.

## Consequences

- **Rotation is cheap.** The KEK wraps DEKs; it never encrypts user data. Rotating
  it re-wraps a row per subject instead of re-encrypting the entire database.
- **Erasure is instantaneous and total**, including backups, which no
  row-deletion scheme can honestly claim.
- **Losing the KEK loses every subject's data.** It must be held in a KMS or HSM
  with its own backup and access audit. This is a real, concentrated operational
  risk, accepted knowingly, and named as such in the runbooks.
- Queries cannot filter on personal fields. Anything the system needs to search,
  sort or aggregate on must be non-personal or blind-indexed, which is a design
  constraint on every future feature and is enforced by review.
- Erasure is recorded in the audit log as an event: the fact that a person
  exercised the right is itself a record that must be kept.
