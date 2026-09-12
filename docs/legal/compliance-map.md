# Compliance map

Every obligation the platform is subject to, mapped to the code, schema or
process that discharges it — and, where nothing yet does, said so.

This is an engineering document. It records what the system does, not legal
advice. Every item marked **confirm** needs a professional to sign it off before
go-live.

---

## India — payments

### RBI (Regulation of Payment Aggregators) Directions, 2025

| Obligation | Position | Implementation |
|---|---|---|
| Non-bank PAs need ₹15 crore net worth at application, ₹25 crore ongoing | **Not applicable — the platform is not a PA** | Money moves buyer → provider → seller. See below |
| Collections held in escrow with a scheduled commercial bank | Not applicable | The platform holds no customer funds at any instant |
| A PA may not operate a marketplace | Not applicable | Settlement is performed by a licensed provider |

**How the position is maintained**, rather than asserted:

- `seller_ledger_account` accepts only `payable` and `reserve` account types. A
  liability account representing held customer funds is not creatable.
- No withdrawal endpoint exists. Settlement is a *hold that expires*, not a
  balance a seller draws down (ADR [0011](../adr/0011-settlement-holds-not-wallets.md)).
- `platform.clearing.*` is an **asset** account — a receivable from the provider,
  not cash. The chart of accounts makes the position legible to an auditor.
- The provider adapter is chosen once at boot from validated configuration.
  There is no runtime switch, so a compromised admin session cannot redirect
  the flow of funds.

**confirm** — obtain written confirmation from the provider that the chosen
settlement model keeps the platform outside the definition of a payment
aggregator.

---

## India — tax

### GST — CGST Act, 2017

| Obligation | Implementation |
|---|---|
| Correct place of supply | `tax.classify` — intra-state, inter-state, export of services, or exempt |
| CGST + SGST intra-state; IGST inter-state | Computed at half-rate each for CGST/SGST, as a GST invoice is actually drawn: rounding the components separately can differ by one paise from rounding the combined rate, and the components are what gets filed |
| Zero-rated export of services | `ExportOfServices`, with the LUT basis recorded in `Explain` |
| **TCS 1% under s.52** | Collected on net taxable value; suppressed for unregistered sellers, because TCS against a supplier with no GSTIN cannot be reported in GSTR-8 |
| GSTR-8 monthly return | Data available from `journal_lines` against `platform.payable.tcs`. **Filing process is manual — confirm with the accountant** |
| Tax invoice with a consecutive serial per financial year | Gapless allocator in `0007_delivery_tax_payouts.sql`. This is the one place serialisation is correct |
| Invoice retention | 8 years; erasure is by crypto-shredding, so the invoice survives the person's erasure request |
| Platform GSTIN on every invoice | `PLATFORM_GSTIN`, required at boot in production |

### Income tax — TDS under s.194-O

| Obligation | Implementation |
|---|---|
| 0.1% on gross amount of sales through the platform | `tax.Compute`, on the value **excluding GST** per CBDT Circular 17/2020 |
| 5% where no PAN is furnished (s.206AA) | `TDSNoPANBps`, applied when `HasPAN` is false |
| Threshold exemption for a resident individual or HUF | `belowThreshold` against `FYGrossSupplyMinor`, which is why `turnover_deltas` tracks per-seller financial-year gross |
| Non-resident sellers outside s.194-O | Rate zero, with the reason recorded in `TDSReason` |
| Form 26Q / 27EQ statements | Data available from the journal. **Filing is manual — confirm** |
| **confirm** TAN registration | Required before the first remittance |

Every determination is narrated in `Breakdown.Explain`, so a seller, an
accountant or an assessing officer reads the reasoning rather than reverse-
engineering a number.

---

## India — consumer and platform regulation

### Consumer Protection (E-Commerce) Rules, 2020

| Rule | Implementation |
|---|---|
| No manipulation of search results | Published, deterministic, reproducible ranking (ADR [0009](../adr/0009-published-deterministic-ranking.md)); `/legal/ranking` |
| Disclose ranking parameters | `Disclosure()` renders them from the same struct the scorer uses, so the page cannot drift from the code |
| No unfair or deceptive trade practice | Fee covenant enforced by a database constraint; all-in pricing shown before payment |
| Seller identity, address and grievance details available | `sellers` schema; **seller-facing surfaces pending** |
| Grievance officer, acknowledgement in 48 hours, resolution in one month | `grievances` schema with SLA fields; `grievance_sla_watch` runs every 10 minutes. **Officer must be appointed and published** |
| Country of origin | Product schema field; **enforcement at publish pending** |
| Refund within a reasonable period | Refund path posts a compensating ledger entry immediately on approval |

### IT (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021

| Rule | Implementation |
|---|---|
| Publish rules, privacy policy and user agreement | Static surfaces; **content pending** |
| Grievance officer with published contact | As above |
| Takedown on actual knowledge or a valid order | `takedowns` schema; **workflow pending** |
| Retain records after removal | `forbid_mutation` on the audit log; removal is a state change, not a deletion |
| Traceability of records for investigation | Hash-chained audit log with actor, IP, user agent and timestamp |

---

## India — personal data

### Digital Personal Data Protection Act, 2023

| Obligation | Implementation |
|---|---|
| Consent, for a specified purpose, itemised | `consents` table with categories: account, transactional e-mail, marketing e-mail, analytics, provenance review, tax reporting |
| Consent recorded against a notice version | `accept_notice_version` at registration; the record is meaningless without it |
| Withdrawal as easy as giving | Per-category withdrawal on the same table |
| **Right to erasure** | Crypto-shredding: destroy the DEK, keep the record (ADR [0008](../adr/0008-crypto-shredding-for-erasure.md)) |
| Right of access / correction | `EraseSubject` and the DSAR schema; **buyer-facing surfaces pending** |
| Data minimisation | Personal fields are enumerated and individually encrypted; adding one is a deliberate act |
| Security safeguards | AES-256-GCM per subject, Argon2id credentials, TLS in transit, `sslmode=disable` refused in production |
| Breach notification | **Process required — see [../runbooks/key-rotation.md](../runbooks/key-rotation.md)** |
| Retention no longer than necessary | Documented per data class in [../arch/05-data-model.md](../arch/05-data-model.md) |

The erasure-versus-retention conflict is the substantive engineering problem
here, and crypto-shredding is the answer: the tax record survives, the person's
data does not.

---

## European Union — for EU buyers and sellers

### Regulation 2019/1150 (Platform-to-Business)

| Article | Obligation | Implementation |
|---|---|---|
| 3 | Plain, accessible terms | Static surfaces; **content pending** |
| 3(2) | **15 days' notice of terms changes** | Fee changes carry 90 days, exceeding it, enforced by `fee_schedules_ninety_day_notice` |
| 5 | **Main ranking parameters and their relative importance** | `/legal/ranking`, generated from the scorer's own parameters |
| 7 | Differentiated treatment disclosed | No differentiated treatment exists; the formula has no seller-identity term |
| 11 | Internal complaint-handling | `grievances` schema; **surfaces pending** |
| 12 | Mediators named in the terms | **Pending** |

### Digital Services Act

| Obligation | Implementation |
|---|---|
| Notice and action mechanism | `takedowns` schema; **workflow pending** |
| Statement of reasons for a restriction | Moderation schema carries a reason; **surfaces pending** |
| Internal complaint handling | As above |
| Trader traceability for marketplaces | Seller KYC schema |
| Recommender-system transparency | Published ranking formula |

### GDPR — where it applies

Crypto-shredding, consent records and the DSAR schema serve Articles 15–17 on
the same mechanism as DPDP. **confirm** whether an EU representative or a DPO is
required given the actual establishment and processing.

### DAC7 (Council Directive 2021/514)

Reportable-seller data — identity, tax identifier, consideration paid per
quarter — is derivable from `sellers` and the journal. **Reporting process
pending**; it becomes relevant only with EU sellers.

---

## Cross-cutting

### RFC 9116 — security contact
`/.well-known/security.txt` is served and must be monitored by a person.

### Accessibility
**Pending** with the SSR surfaces. WCAG 2.2 AA is the target.

---

## Honest status

| Area | Status |
|---|---|
| Payment-aggregation posture | **Structurally enforced** — schema refuses a wallet |
| GST and income-tax computation | **Implemented and tested** — 200k-iteration conservation test |
| Statutory filing | **Data available, process manual** |
| Ranking transparency | **Implemented and published** |
| Fee-change notice | **Enforced by a database constraint** |
| Consent and erasure | **Implemented**; user-facing surfaces pending |
| Grievance and takedown | **Schema and SLA watch exist**; workflows pending |
| Seller KYC and disclosure | **Schema exists**; surfaces pending |
| DAC7 | Not started — not yet relevant |
| Accessibility | Not started |

The pending rows are surfaces over schema that already exists and constraints
that are already enforced — not missing foundations. Where an obligation is not
yet discharged, it is listed here rather than omitted, because a compliance map
that only lists successes is a liability in exactly the situation it exists for.
