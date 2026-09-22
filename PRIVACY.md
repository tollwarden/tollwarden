# TollWarden — Privacy Policy

**Last updated: 2026-09-22**

This policy explains what data the TollWarden service ("the Service," "we," "us"), operated by **TollWarden, LLC**, a Colorado limited liability company, collects and how we handle it. It should be read alongside our [Terms of Use](TERMS.md).

## 1. Summary (the important part)

TollWarden is an **advisory, non-custodial** payment-security scanner. It is designed to *avoid* retaining sensitive data:

- We process the payment metadata you submit **in memory** to produce a verdict, and we **do not retain it in plaintext**. The one exception is opt-in: if you turn on human approvals, a short excerpt of a flagged payment is held for about a day so a person can review it ([§2](#2-what-we-collect-and-why)).
- Our tamper-evident audit log stores only a **cryptographic hash (SHA-256)** of each scanned payment plus a few non-sensitive transaction facts — **never** the plaintext `description`, `reason`, `metadata`, or `content` you submit.
- To enforce limits and detect attacks, we keep pseudonymous history keyed to a **hash** of your API key: recent payment rates, the counterparties your account has paid, and the merchant addresses it has seen.
- We **never** receive, store, or have access to private keys, wallet seed phrases, or funds. We are not a custodian or payment processor.

## 2. What we collect and why

Most of what we keep is tied to your **account**: the SHA-256 hash of your API key, never the key itself. Scans made without an API key are tied to the self-chosen `agent_id` or the `payer` address instead. "Size cap" below means each store holds a fixed maximum number of entries (100,000 by default) and drops the oldest first once full.

| Data | Purpose | Retention |
|---|---|---|
| **Scan payloads** (payment fields + optional `context.content` and `context.offer`) | Processed in memory to compute a verdict | Not retained in plaintext; discarded after the response (except the approval excerpt below) |
| **Audit records**: SHA-256 hash of the payment, `scan_id`, timestamp, direction, verdict, risk score, caller `agent_id`, `network`, `pay_to`, USD amount, which checks fired, and the verdict signature. Approval decisions also record how long the human took to decide | Tamper-evident record of each **decision** for dispute/regulatory review | **24 months** |
| **Nonce fingerprints** (`network:payer:nonce` + `scan_id`) | Replay-attack detection | `NONCE_TTL_HOURS` (default 24h) |
| **Scan index**: payment hash, `pay_to`, resource domain, verdict, hashed API key, timestamp | Lets a delivery-outcome report be verified against a scan we actually performed, once per scan | Until displaced by the size cap |
| **Merchant pins**: (a) a shared observation per resource domain (first `pay_to` seen, times seen, CDP cross-check status); (b) your account's own pin per domain (hashed API key + domain → `pay_to`) | Payment-address-rotation and address-poisoning detection | Until cleared by the operator or displaced by the size cap; your account's pins are deleted when you revoke the key |
| **Account activity**: recent scan timestamps and USD values, the counterparty addresses your account has paid, and cumulative scanned spend per counterparty | Rate, spend-cap, and first-contact enforcement; deciding when to run deep analysis | Rate data older than one hour is dropped at your next scan. Counterparty and spend history is kept until you revoke the key or it is displaced by the size cap. Key rotation carries it over |
| **API-key accounts**: key hash, creation time, self-chosen `agent_id`, call and verdict counts, last-used time, plan and expiry, and approval statistics (counts plus your last 50 decisions' timing, decision, and delivery outcome) | Free-tier metering, plans, your usage dashboard. Approval statistics are shown **only to you** | Until you revoke the key. A hash-only tombstone remains so a revoked key keeps failing |
| **Human approvals** (opt-in, per account): your webhook URL and format, plus a webhook signing secret. For each flagged payment sent for approval: payee, amount, network, asset, resource URL (up to 500 characters), `description` (up to 300 characters, **plaintext**), `agent_id`, risk score, checks fired, and a hash of the one-time decision token | Delivering the flagged payment to **your** webhook and recording the human decision | Webhook settings until you change them or revoke the key. Approval records are deleted about 24 hours after creation |
| **Delivery outcomes**: per counterparty address and per resource domain, counts of delivered / not delivered / partial / wrong content, receiptless settlements, reporting-account hashes, and first/last dates. Also a count of scans per counterparty | Measured delivery history shown in reputation lookups and future scans | Until displaced by the size cap |
| **Injection incidents**: the implicated address, the check that caught it, the declared payment origin, the scanning `agent_id` or payer, `scan_id`, and timestamp | Warning every agent about a wallet that was planted through prompt injection | Until displaced by the size cap |
| **Reputation reports**: address, category, reason (up to 1,000 characters), `reporter_agent_id`, optional evidence URL, and timestamp | Shared, user-submitted counterparty registry | Retained as user-generated content ([see §5](#5-the-reputation-registry)) |
| **Signed disputes**: address, statement, signature, and timestamp | Letting a reported wallet's owner respond | Retained and shown publicly alongside the reports |
| **IP address** | Rate limiting on free endpoints: key issue, rotation, and revocation; approval configuration and decisions; reports and disputes; outcome reports; and trust evaluations | Held in memory only; not written to our store. Our hosting provider keeps standard request logs, which include IP addresses, under its own retention policy |

We publish aggregate service statistics (total scans, verdict split, distinct agents, uptime). These are totals only, with no per-agent or per-payment data.

We do **not** use tracking cookies, advertising networks, analytics pixels, or behavioral profiling.

## 3. What we deliberately do NOT collect

The plaintext of the sensitive fields TollWarden exists to detect — API keys, secrets, seed phrases, PII in `description`/`reason`/`metadata`, and the `content` you pass for injection analysis — is processed transiently and **is not written to disk**, with one opt-in exception: when you enable human approvals, the first 300 characters of a flagged payment's `description` are held with the approval record for about a day and sent to your webhook (§2). Detected secrets are **redacted** in our scan responses (first 4 + last 2 characters). We hold no bank, card, or wallet-credential data.

## 4. Legal basis / how we use data

We use the data above solely to (a) provide the scanning service you request, (b) detect and prevent abuse of the Service, and (c) keep an integrity-verifiable record of the decisions we rendered. We do **not** sell your data or share it for advertising.

## 5. The reputation registry

Reputation reports you submit are **user-generated content**: an address, a category, your free-text reason, your self-asserted `reporter_agent_id`, and an optional evidence URL. Anyone who looks up that address sees a summary built from the reports: counts, categories, dates, and a weighted score. The summary does not show your reason text or your `reporter_agent_id`. A report's weight fades over time (90-day half-life), but the report itself is kept until it is removed or displaced by the size cap. Do not include personal data or secrets in a report. You are responsible for the content of your reports (see the Terms).

If your wallet has been reported, you can attach a **signed rebuttal** yourself: sign the dispute message with the wallet's key and submit it to `POST /v1/reputation/dispute`. Rebuttals are shown in full alongside the reports and never erase them. To request removal of a report, contact **abuse@tollwarden.com**.

## 6. Sub-processors / third parties

We rely on a small number of service providers who may process data on our behalf:

- **Render** (render.com) — application hosting and storage of the audit log/state. Render serves traffic through its CDN provider (Cloudflare).
- **Coinbase Developer Platform (CDP)** — the x402 facilitator that verifies and settles payments. Note: the *payment itself* is initiated by your wallet and settles on-chain; TollWarden is advisory and does not route your funds. When the operator enables the merchant cross-check (`CDP_PIN_VERIFY=on`), we also ask CDP's public merchant index which resources a merchant's `pay_to` address serves. We send the **merchant's address only**, never yours, and no amounts, keys, or payload contents.
- **Zoho** — business email for our contact addresses.
- **ScoutScore** (scoutscore.ai) — optional external trust ratings for merchant domains (only when the operator enables `SCOUTSCORE=on`). When enabled, we query ScoutScore with the **resource domain only** (e.g. `api.example.com`) from scanned payments — never wallet addresses, amounts, API keys, payload contents, or your identity. Responses are cached server-side and surfaced in scan results as a clearly labeled third-party signal.

If you configure a human-approval webhook, including a Slack webhook, we send each flagged payment's facts (listed in §2) to that destination on your instruction. What happens to them there is governed by that destination's operator.

We do not otherwise disclose data except where required by law, to enforce our Terms, or to protect the rights and safety of users or the public.

## 7. Your rights

Depending on your jurisdiction (e.g. GDPR/CCPA), you may have rights to access, correct, or delete personal data we hold about you. Because most of what we retain is **pseudonymous** (payment hashes, wallet addresses, self-chosen agent IDs) and not linked to a real-world identity, we may be unable to associate a request with a specific person without additional information. To make a request, contact **contact@tollwarden.com**. You can also delete your own account at any time by revoking your API key (`POST /v1/keys/revoke`). This deletes the account record, its webhook settings, and its activity history (pins, rate data, counterparties, cumulative spend). Note that audit records are retained for integrity and legal-defensibility reasons and may be exempt from deletion for their retention period.

## 8. Security

Data in transit is protected by TLS. API keys are stored hashed. The audit log is hash-chained so tampering is detectable, and (in production) shipped to write-once storage. No system is perfectly secure; we cannot guarantee absolute security. See our public security review (`SECURITY-AUDIT.md`) for our controls and known limitations, and report vulnerabilities to **security@tollwarden.com**.

## 9. Children

The Service is not directed to children and is intended for use by developers and autonomous agents. We do not knowingly collect personal data from children.

## 10. Changes

We may update this policy; material changes take effect when posted with a new "Last updated" date.

## 11. Contact

Privacy questions: **contact@tollwarden.com**
Data controller: **TollWarden, LLC**, Colorado, USA
