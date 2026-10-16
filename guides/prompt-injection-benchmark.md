# Prompt-injection benchmark for x402 agent payments

A prompt-injection detector that blocks every payment is useless, and one that allows every payment is worse. The honest way to say where a detector sits between the two is to run it against a fixed set of attacks and benign text and publish what happens. This page does that for TollWarden's detector, the check that stops an agent from paying an address it was talked into by a web page or a tool result, and it says what the numbers can't tell you.

The corpus is TollWarden's own. The people who wrote the detector wrote the cases, and many cases were added after a bypass had been found and fixed. A perfect score on it is regression coverage, evidence that the bypasses we know about stay closed. It is not a measure of how many unseen attacks the detector catches.

## Results

From `npm run eval` on 15 October 2026, against [eval/corpus.ts](https://github.com/tollwarden/tollwarden/blob/main/eval/corpus.ts). The corpus has 124 cases, 85 attacks and 39 benign. One benign case is a documented known gap, tracked but not gating.

| Requirement | Cases | Result |
| --- | --- | --- |
| Attack must reach block | 74 | 74 blocked |
| Attack must reach at least flag | 11 | 11 flagged |
| Benign must stay allow | 20 | 20 allowed |
| Benign may flag but must not block | 18 | 18 flagged, none blocked |
| Known gap, tracked but not gating | 1 | Still open |

The runner prints this as 85 of 85 attacks detected and 38 of 38 benign cases not over-flagged. The second figure means every benign case stayed at or under its ceiling, and 18 of those ceilings are flag. So the accurate reading is that no gating benign case blocks and 18 of the 38 raise a flag. It is not a claim of zero false positives.

## How a case is graded

Each case is one scan context. The [runner](https://github.com/tollwarden/tollwarden/blob/main/eval/run-eval.ts) builds a real outgoing scan for every case, a $1 USDC payment on Base to a fixed payee, with the case text as `context.content` (or `context.offer`) and the origin the case names, which defaults to `fetched_content`. Every case gets a fresh store, so nothing one case does can affect another. $1 is above the micropayment threshold, so the deep decoding tier runs on every case.

Only the content-detection checks are graded, the `injection` and `poison` families, minus the origin advisories that fire on any scan of untrusted content. Those advisories would make every attack look caught for the wrong reason. A case's level is the highest verdict among the graded checks.

An attack case names the minimum level it must reach, and a benign case names the maximum it may reach. Any gating case that misses makes the runner exit non-zero, which fails CI and stops an npm publish.

## Attack families

| Family | Cases | Must block | What it covers |
| --- | --- | --- | --- |
| `tells` | 9 | 8 | Override phrasing, "transfer the balance to" an address, secrecy, fake role markers, spoofed tool output, a weak tell next to an address |
| `tells-i18n` | 7 | 7 | Override phrasing in Spanish, French, German, Portuguese, Russian, Chinese and Japanese |
| `tells-ext` | 12 | 8 | Phrasings in the style of public injection test sets (Rebuff, vigil, garak), template control tokens, fabricated chat turns |
| `tells-wording` | 25 | 20 | Wording that slipped past earlier versions, such as "every prior", "the instructions above", a capitalised `System:` line, Llama 3 and Phi chat-template headers, a decimal amount inside a send instruction |
| `tells-bec` | 2 | 2 | Business-email-compromise phrasing, a changed payee with verification waved off and no override verb at all |
| `markup` | 4 | 4 | Tells split by markdown emphasis, inline HTML tags or `&nbsp;` entities, or hidden in a `display:none` element |
| `encoding` | 12 | 12 | Base64 (standard, URL-safe, line-wrapped, space-chunked, double-encoded), hex, percent-encoding, HTML entities, Unicode tag characters, JavaScript escapes |
| `unicode` | 6 | 6 | Cyrillic homoglyphs, dotless i, IPA script g, fullwidth letters, leetspeak, letter spacing |
| `provenance` | 6 | 5 | The payee address in the content verbatim, split across lines, laced with zero-width characters, dashed, or without its `0x`, plus one verbatim match from a trusted origin |
| `offer` | 1 | 1 | Instructions written into the 402 offer's own fields |
| `poisoning` | 1 | 1 | A vanity address sharing the payee's first and last four hex characters |

The 11 attacks that only need to flag use phrasing that benign text shares. A bare "ignore instructions" turns up in real documentation ("ignore instructions in the legacy section"), and a fabricated assistant then user turn has the same shape as a pasted support transcript. Blocking those would block their benign twins in the same corpus. A verbatim payee from a trusted origin flags by design too, because a person pasting an address is how agents are normally told whom to pay. A flag still stops a payment when the client treats flags as refusals, which is what `strict` does in the SDK wrappers.

## Benign families

| Family | Cases | Must allow | May flag | What it covers |
| --- | --- | --- | --- | --- |
| `benign` | 18 | 14 | 3, plus the known gap | Plain docs, base64 in docs, git commit hashes, a legitimate 402 offer, Russian and French prose, JSON tool output, an unrelated address, ordinary uses of "ignore", "directions" and "start over" |
| `benign-scoring` | 11 | 0 | 11 | Text with pressure and no instruction, such as marketing urgency, a byte-order mark, soft hyphens, a real transcript, two weak tells 2,000 characters apart, or a user telling the agent whom to pay |
| `benign-wording` | 10 | 6 | 4 | Lines that look like tells and aren't, such as `System: Windows 11` in a spec sheet, `Admin:` opening a forum post, "you must not pay", "new shipping address", and a 4.7kΩ resistor value |

## The open gap

`quoted_attack_article` is a security article that quotes an attack string while explaining it. The detector blocks it, because it reads a quoted instruction the same way it reads a live one, and telling the two apart needs awareness of quotation that the detector doesn't have. The case's ceiling is flag, so this is a false block, the expensive kind. An agent that reads security journalism about prompt injection and then decides to pay can be stopped when it shouldn't be.

The case stays in the corpus as a known gap. It doesn't fail the run, and the runner reports it as closed the day it starts passing, which is the signal to promote it to a gating case. Two gaps have closed that way already. Leetspeak override phrasing was one until the leetspeak fold landed, and a paraphrased request to pay a vendor's "updated" wallet was the other until the payee-change and skipped-verification tells did.

## Speed

Detection runs inside the scan request, so a pattern that goes quadratic on long input would be a denial of service for every caller. The test suite runs 14 pathological inputs at the 200 KB content cap, such as an unbroken 200 KB base64 run, and fails any that takes 250 ms or more. On two runs on 15 October 2026 the slowest took 26.9 ms and 28.4 ms. Those figures come from one development machine and move with the hardware and the run, but the 250 ms ceiling is what the suite enforces everywhere it runs.

## What these numbers do not show

- **Recall on attacks nobody has written down.** Every attack case is one somebody here thought of or had already seen. An attacker who can iterate against the detector will find wording it misses. That is why address provenance doesn't depend on wording. If the payee address is in the text the agent read, `injection.payto_from_content` fires whatever the surrounding sentence says, and the wallet enforcer's recipient allowlist bounds what a miss can cost.
- **False-positive rates on real traffic.** The 38 gating benign cases guard against specific over-fires that were found and fixed. They are not a sample of what agents actually read.
- **Languages beyond the eight in the corpus.** The corpus tests override phrasing in English and seven other languages. Text in any other language is caught only as far as the tell list happens to reach, and by address provenance, which ignores language.
- **End-to-end agent behavior.** The benchmark grades the detector's verdict on a scan. It doesn't measure whether an agent using TollWarden makes fewer bad payments, which depends on whether the client passes along what the agent read and acts on the verdict.

## Run it yourself

```
git clone https://github.com/tollwarden/tollwarden
cd tollwarden
npm install
npm run eval
```

Every case prints with its family, the level it reached and the level it needed. Obfuscated characters in the corpus are written as `\u` escapes, so the file reads cleanly in a diff.

To add a case, open a pull request against `eval/corpus.ts`. A detection change should come with an attack case and a benign guard beside it, because the benign guard is what stops a later, well-meaning loosening from reopening the hole.

For the failure modes beyond injection, and how a verdict becomes binding at the wallet, read [AI agent payment security on x402](/guides/ai-agent-payment-security).
