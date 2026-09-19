// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Prompt-injection-triggered payment detection.
 *
 * Fast tier (always runs, ~sub-ms):
 *  1. Provenance — payments whose decision originated from content the agent
 *     just read (tool result / fetched page) rather than its own planning step.
 *  2. Injection tells in the just-read content. Tells are weighted (strong
 *     imperative/override phrasing = 2, contextual pressure = 1) and a tell
 *     occurring near an address-like token earns a proximity boost — an
 *     instruction next to an address is far stronger signal than the same
 *     phrase elsewhere in a 200KB page. Weight-1 tells only compound when they
 *     cluster (injections are compact; a 200KB page is not one message), and
 *     two "pressure" tells (urgency, transcript shape, hidden characters)
 *     never block on their own — pressure without an instruction is not an
 *     injection. The content is also scanned with HTML tags, entities and
 *     markdown emphasis stripped: fetched content IS markup, and a tell split
 *     by <b> or ** is still a tell.
 *  3. Address provenance — pay_to appearing in that content, including split
 *     across whitespace/separators or laced with invisible characters (an
 *     obfuscated match is treated as deliberate concealment and blocks outright).
 *     context.offer (the raw 402/discovery payload) is the sanctioned channel
 *     for protocol data: pay_to is EXPECTED there and exempt from #3, but the
 *     offer is still counterparty-authored, so #2's tells scan runs on it.
 *
 * Deep tier (runs above the micropayment threshold or on untrusted-origin
 * content; linear in the 200KB content cap — every regex here is bounded or
 * fixed-width, see the latency test):
 *  4. Base64-obfuscated payloads decoded and rescanned — standard and URL-safe
 *     alphabets, MIME-style line-wrapped and space-chunked blobs, one level of
 *     double-encoding.
 *  5. Other encodings: hex, percent(URL)-encoding, HTML numeric entities,
 *     JS/JSON \x / \u escapes.
 *  6. Unicode tag-character smuggling (U+E0020–E007E "invisible ASCII")
 *     decoded and rescanned.
 *  7. Unicode-skeleton rescan: NFKC + invisible-char strip + confusable
 *     (Cyrillic/Greek/IPA/small-cap homoglyph) folding, which NFKC alone does
 *     not do.
 *  8. Leetspeak (1gn0re) and letter-spacing (i g n o r e) folded and rescanned.
 */
import type { CheckResult, PaymentDetails, PaymentOrigin, ScanContext } from "../types.ts";

// ---------------------------------------------------------------------------
// Invisible characters & confusables
// ---------------------------------------------------------------------------

// Characters that render as nothing (or nearly nothing) and are used to hide
// text or break up token matching: Mongolian vowel separator, zero-width
// space/joiners, word joiner + invisible operators, bidi overrides, BOM, and
// the Unicode tag block (invisible ASCII mirror, U+E0000–E007F).
// Deliberately NOT in the tell (but still stripped for matching):
//   * variation selectors (FE00–FE0F) — every "❤️" carries one;
//   * soft hyphen (U+00AD) — typeset web prose (German, hyphenation CSS) is
//     full of them;
//   * a BOM at offset 0 — every UTF-8-with-BOM file starts with one.
const TELL_INVISIBLE =
  /(?:(?<!^)﻿|[᠎​-‍⁠-⁤‭‮\u{E0000}-\u{E007F}])/u;
const STRIP_INVISIBLE_G =
  /[­᠎​-‍⁠-⁤‭‮︀-️﻿\u{E0000}-\u{E007F}]/gu;

/** Remove invisible/zero-width/tag characters. Exported for cross-detector use. */
export function stripInvisible(text: string): string {
  return text.replace(STRIP_INVISIBLE_G, "");
}

// Homoglyphs NFKC does NOT fold: visually-identical Cyrillic/Greek/IPA/
// small-capital letters mapped to their Latin lowercase twins (tell regexes
// are case-insensitive, so folding capitals to lowercase Latin is fine).
// Curated for visual identity — not a full TR39 confusables table; the
// mixed_script tell below covers lookalikes this table does not know.
const CONFUSABLES: Record<string, string> = {
  // Cyrillic lowercase
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
  "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w",
  "ғ": "f", "ѡ": "w", "ԍ": "g", "ⅼ": "l",
  // Cyrillic capitals
  "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o",
  "Р": "p", "С": "c", "Т": "t", "У": "y", "Х": "x", "І": "i", "Ѕ": "s",
  "Ј": "j", "Ԁ": "d", "Ԛ": "q", "Ԝ": "w",
  // Greek lowercase
  "ο": "o", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "υ": "u", "ι": "i",
  "κ": "k", "χ": "x", "ε": "e", "η": "n", "ω": "w", "γ": "y",
  // Greek capitals
  "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k",
  "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
  // Latin lookalikes outside Cyrillic/Greek: dotless i, script g, dotless j,
  // IPA and small capitals, Latin letter dental click.
  "ı": "i", "ɡ": "g", "ȷ": "j", "ɩ": "i", "ǀ": "l",
  "ɢ": "g", "ʜ": "h", "ɪ": "i", "ʟ": "l", "ɴ": "n", "ʀ": "r", "ʏ": "y", "ʙ": "b",
  "ᴀ": "a", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ᴊ": "j", "ᴋ": "k", "ᴍ": "m", "ᴏ": "o",
  "ᴘ": "p", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ᴢ": "z", "ꜱ": "s",
};
// Scripts/blocks the fold table draws from. Also the "non-Latin letter"
// class for the mixed_script tell.
const CONFUSABLE_CLASS = "\\u0131\\u0237\\u01C0\\u0250-\\u02AF\\u0370-\\u03FF\\u0400-\\u052F\\u1D00-\\u1D7F\\uA730-\\uA7FF\\u2170-\\u217F";
const CONFUSABLE_PRESENT = new RegExp(`[${CONFUSABLE_CLASS}]`);

/**
 * Skeleton form for rescanning: NFKC-normalize, strip invisible chars, fold
 * confusable homoglyphs to Latin. "іgnоre" (Cyrillic і/о) → "ignore".
 */
export function skeleton(text: string): string {
  let s = text.normalize("NFKC").replace(STRIP_INVISIBLE_G, "");
  if (CONFUSABLE_PRESENT.test(s)) {
    s = [...s].map((c) => CONFUSABLES[c] ?? c).join("");
  }
  return s;
}

// ---------------------------------------------------------------------------
// Markup stripping (fast tier)
// ---------------------------------------------------------------------------

const NAMED_ENTITIES: Record<string, string> = {
  nbsp: " ", ensp: " ", emsp: " ", thinsp: " ", amp: "&", lt: "<", gt: ">",
  quot: '"', apos: "'", shy: "", zwnj: "", zwj: "",
};
// <tag ...> — `[^<>]*` cannot cross the next "<", so the scan is linear.
const HTML_TAG_G = /<\/?[a-zA-Z][^<>]*>/g;
// Tags, named entities, or markdown emphasis openers. snake_case does not
// count — the underscore must open a token.
const MARKUP_PRESENT = /<\/?[a-zA-Z]|&[a-z]{2,6};|\*\*|\*\w|(?<!\w)_\w|~~|`/;

/**
 * Strip HTML tags, decode the common named entities, and drop markdown
 * emphasis characters. Fetched content is markup; "**Ignore** all
 * <b>previous</b>&nbsp;instructions" must scan as the sentence it renders as.
 * Not applied to role/template markers (which ARE markup) — the raw text is
 * scanned as well and the two hit sets are merged.
 */
export function stripMarkup(text: string): string {
  if (!MARKUP_PRESENT.test(text)) return text;
  return text
    .replace(HTML_TAG_G, " ")
    .replace(/&([a-z]{2,6});/g, (m, name: string) => NAMED_ENTITIES[name] ?? m)
    .replace(/[*_~`]+/g, "");
}

// ---------------------------------------------------------------------------
// Injection tells
// ---------------------------------------------------------------------------

/**
 * "instruction" tells phrase a directive (override, pay, hide, refocus).
 * "pressure" tells are shape or context (urgency, transcript form, hidden
 * characters, mixed scripts). Two pressure tells never block on their own.
 */
type TellKind = "instruction" | "pressure";

interface Tell {
  id: string;
  re: RegExp;
  label: string;
  /** 2 = strong (unambiguous override/redirect phrasing), 1 = contextual. */
  weight: 1 | 2;
  kind: TellKind;
}

// Verbs that head an instruction-override phrase. Kept in sync with the open
// heuristic sets (Rebuff, vigil-llm) whose corpora we benchmark against, so a
// phrasing they flag is not one we silently miss.
// "override" and "drop" are deliberately absent: "later rules override the
// previous rules" and "drop the following commands into a terminal" are docs
// prose. The precedence tell covers "overrides all previous …".
const OVERRIDE_VERBS =
  "ignore|disregard|skip|forget|neglect|overlook|omit|bypass|discard|dismiss|abandon|disobey|" +
  "pay\\s+no\\s+attention\\s+to|(?:cease|stop)\\s+(?:following|obeying)|no\\s+longer\\s+follow|" +
  "(?:do\\s+not|don'?t)\\s+(?:follow|obey|comply\\s+with|adhere\\s+to|heed)";
// Determiners between verb and adjective ("all of the", "every", "your").
const OVERRIDE_DET =
  "(?:(?:all|any|each)\\s+(?:of\\s+)?|every\\s+|the\\s+|your\\s+|these\\s+|those\\s+|my\\s+|our\\s+)?(?:the\\s+)?";
// Positional adjectives ("previous", "above", …). Tolerates a conjoined pair
// so "any previous AND following instructions" (a canonical injection string)
// matches — strict adjacency previously broke on the "and following" join.
const OVERRIDE_ADJ =
  "(?:previous|prior|preceding|above|foregoing|earlier|initial|original|following)(?:\\s+and\\s+(?:previous|prior|preceding|above|foregoing|earlier|initial|original|following))?";
// A noun modifier may sit between adjective and object: "previous SYSTEM prompt".
const OVERRIDE_MOD = "(?:\\s+(?:system|user|operator|developer|safety|default|standing|written|given|assigned))?";
// High-signal objects only. Deliberately excludes context/input/data/message —
// those appear constantly in benign prose ("ignore the previous message"), so
// at our blocking weights they are net false positives, not coverage.
const OVERRIDE_OBJ = "instructions?|prompts?|rules?|guidance|directives?|directions?|commands?";

const INJECTION_TELLS: Tell[] = [
  // Strong override: verb + (adjective, possibly conjoined) + high-signal
  // object. Adjective REQUIRED here — that anchor is what keeps weight 2 (which
  // can block on its own from an untrusted origin) precise.
  { id: "override", weight: 2, kind: "instruction", re: new RegExp(`\\b(?:${OVERRIDE_VERBS})\\s+${OVERRIDE_DET}${OVERRIDE_ADJ}${OVERRIDE_MOD}\\s+(?:${OVERRIDE_OBJ})\\b`, "i"), label: "instruction-override phrasing" },
  // Postpositive form: "ignore the instructions ABOVE / you were given". As
  // unambiguous as the adjective-first form. "below" is deliberately absent —
  // "skip the instructions below if you already installed" is real docs prose.
  { id: "override_post", weight: 2, kind: "instruction", re: new RegExp(`\\b(?:${OVERRIDE_VERBS})\\s+${OVERRIDE_DET}(?:${OVERRIDE_OBJ})\\s+(?:above|before|earlier|so\\s+far|up\\s+to\\s+(?:this|now)|you\\s+(?:were|have\\s+been)\\s+given)\\b`, "i"), label: "instruction-override phrasing (postpositive)" },
  // Loose override: same verbs + object but NO adjective ("ignore instructions",
  // "forget the conversation"). Weight 1 — bare verb+object can appear benignly
  // ("you can ignore instructions in the legacy section"), so it flags on its
  // own and only blocks when a second signal is present.
  { id: "override_loose", weight: 1, kind: "instruction", re: new RegExp(`\\b(?:${OVERRIDE_VERBS})\\s+${OVERRIDE_DET}(?:${OVERRIDE_OBJ}|conversation)\\b`, "i"), label: "instruction-override phrasing (loose)" },
  // Non-English variants of the same override phrasing (es/fr/de/pt/ru/zh/ja).
  { id: "override_i18n", weight: 2, kind: "instruction", re: /ignora\s+(?:todas\s+)?las\s+instrucciones\s+anteriores|ignore[zr]?\s+les\s+instructions\s+pr[ée]c[ée]dentes|ignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+anweisungen|ignore\s+as\s+instru[çc][õo]es\s+anteriores|игнорируй(?:те)?\s+(?:все\s+)?предыдущие\s+инструкции|忽略(?:之前|以上|所有)的?(?:指令|指示|说明)|以前の指示を無視/i, label: "instruction-override phrasing (non-English)" },
  { id: "new_instructions", weight: 2, kind: "instruction", re: /\b(?:new|updated|real|actual|true|revised)\s+instructions?\s*(?:[:>-]|\bfollow\b|\bbelow\b)|\bhere\s+are\s+(?:your|the)\s+(?:new|real|actual|updated|revised)\s+instructions\b/i, label: "injected replacement instructions" },
  // Context-reset suffix ("… and start over/anew/afresh/from scratch"). Weight
  // 1 companion to the override tells; the leading "and" keeps it from firing
  // on a bare benign "start over".
  // "start over" is deliberately excluded — it is common benign English ("close
  // it and start over"). The retained variants are rare enough in prose to
  // carry signal; the "…and start over" injections all also trip an override
  // verb we already catch, so nothing is lost.
  { id: "context_reset", weight: 1, kind: "instruction", re: /\band\s+(?:start\s+(?:anew|afresh)|begin\s+(?:anew|afresh)|start\s+from\s+scratch|start\s+from\s+the\s+beginning)\b/i, label: "context-reset phrasing" },
  // Up to two intervening words ("you must NOW pay"), none of them a negation
  // ("you must not pay" is the opposite instruction).
  { id: "pay_command", weight: 1, kind: "instruction", re: /\b(?:you\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to|will\s+need\s+to)|be\s+sure\s+to|make\s+sure\s+(?:to|you)|proceed\s+to|go\s+ahead\s+and)\s+(?:(?!not\b|never\b|no\b)\w+\s+){0,2}(?:pay|send|transfer|authorize|approve|settle|wire|remit)\b|\bimmediately\s+(?:pay|send|transfer|authorize|approve|settle|wire|remit)\b/i, label: "imperative payment command" },
  // NOT /i: case-insensitivity would loosen the strict base58 class into
  // matching any long alphanumeric token. Verb/preposition case variants
  // (lowercase / Capitalized / ALLCAPS) are spelled out instead. The span
  // between verb and preposition admits a decimal point only inside a number
  // ("Send 1.5 USDC to 0x…"), and the address may be introduced by "to:",
  // "to the wallet", backticks/quotes/brackets.
  { id: "send_to_address", weight: 2, kind: "instruction", re: /\b(?:[Ss]end(?:ing)?|SEND|[Pp]ay(?:ing|ment)?|PAY(?:MENT)?|[Tt]ransfer(?:ring)?|TRANSFER|[Ff]orward|FORWARD|[Rr]oute|ROUTE|[Rr]edirect|REDIRECT|[Dd]eposit|DEPOSIT|[Ww]ire|WIRE|[Rr]emit|REMIT|[Ww]ithdraw|WITHDRAW|[Mm]ove|MOVE|[Dd]irect|DIRECT)\b(?:[^.\n]|\.(?=\d)){0,80}\b(?:[Tt]o|TO|[Aa]t|AT|[Ii]nto|INTO)\b:?\s*(?:(?:[Tt]he|THE|[Tt]his|THIS)\s+)?(?:(?:[Aa]ddress|ADDRESS|[Ww]allet|WALLET|[Aa]ccount|ACCOUNT)\s*:?\s*)?[`"'<(\[]*\s*(?:0x[0-9a-fA-F]{6,}|[1-9A-HJ-NP-Za-km-z]{32,44})/, label: "payment redirection to embedded address" },
  // Concealment from the principal, phrased as an imperative: "do not tell /
  // disclose / reveal / mention this to the user", "the user doesn't need to
  // know". Verbs like show/report and the "without notifying the user"
  // participle form are software-docs prose ("dismisses without notifying the
  // user") and live in the weight-1 tell below.
  { id: "secrecy", weight: 2, kind: "instruction", re: /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|disclose|reveal|mention\s+(?:this\s+)?to)\s+(?:this\s+|it\s+|that\s+|anything\s+)?(?:to\s+)?(?:the\s+|your\s+)?(?:user|human|owner|operator|principal|account\s+holder)\b|\bthe\s+(?:user|human|owner|operator)\s+(?:does\s+not|doesn'?t|must\s+not|need\s+not|should\s+not|shouldn'?t)\s+(?:need\s+to\s+)?(?:know|be\s+told|be\s+informed)\b/i, label: "concealment instruction" },
  // Softer concealment ("don't tell anyone", "keep this between us", "without
  // informing the user"): common enough in benign prose to sit at weight 1.
  { id: "secrecy_loose", weight: 1, kind: "instruction", re: /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+(?:anyone|anybody)\b|\bkeep\s+this\s+(?:secret|confidential|private|between\s+us|to\s+yourself)\b|\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|owner|operator)\b/i, label: "concealment instruction (loose)" },
  // Spoofed role/system markers. Case-insensitive: "System:" at line start and
  // "<SYSTEM>" are the same spoof as their lowercase forms. Covers bracketed
  // and tagged system/admin/developer/operator roles, chat-template system
  // slots (<|system|>, Llama-3 header ids) and a markdown heading naming a
  // system/admin/developer PROMPT (a bare "## Developer" heading is a docs
  // page). The line-start colon form is "system" only — "Admin:" opens forum
  // posts — and a "System:" followed by an OS name is a spec sheet.
  { id: "role_marker", weight: 2, kind: "instruction", re: /<\/?(?:system|assistant|instructions?|admin|administrator|developer|operator|sys)\s*>|\[\/?(?:system|admin|administrator|developer|operator|sys)\]|^[ \t>]*system\s*:(?!\s*(?:windows|mac|linux|ubuntu|android|ios|requirements?)\b)|<\|(?:system|start_header_id\|>\s*system\s*<\|end_header_id)\|>|^#{1,6}\s*(?:system|admin|developer)\s+(?:prompt|message|instructions?)\s*$/im, label: "spoofed role/system marker" },
  // Chat-template / tool-structure spoofing, incl. Guidance-language markers
  // ({{#system~}}, {{/user~}}) — templating tokens with no place in prose, and
  // a JSON/YAML role field naming a privileged role (quoted JSON shape or a
  // whole YAML line, so "Role: Developer Advocate" in a job post stays out).
  { id: "tool_spoof", weight: 1, kind: "instruction", re: /<\|im_start\|>|<\|(?:user|assistant|im_end|begin_of_text)\|>|<<\/?SYS>>|\[\/?INST\]|["']role["']\s*:\s*["'](?:system|developer)["']|^\s*role\s*:\s*(?:system|developer)\s*$|\{\{[#/](?:system|user|assistant)~?\}\}/im, label: "spoofed chat-template/tool structure" },
  // Model boundary/control tokens smuggled into content to fake a turn/session
  // break before injected instructions. Unambiguous — never legitimate prose.
  { id: "control_token", weight: 2, kind: "instruction", re: /<\|endoftext\|>|<\|eot_id\|>|<\|end\|>|<\|endofprompt\|>|<end\s+of\s+(?:session|turn|conversation|transcript)>/i, label: "smuggled model boundary/control token" },
  // Fabricated dialogue turns: two role-labelled lines in a row, in either
  // order — assistant→user puppets the request, user→assistant puppets the
  // compliance. Blank lines between them are tolerated ("\n\nHuman: …
  // \n\nAssistant:"). Weight 1 — a genuine transcript has the same shape.
  { id: "turn_spoof", weight: 1, kind: "pressure", re: /(?:^|\n)[ \t>]*(?:assistant|ai|user|human)\s*:[^\n]*\n(?:[ \t]*\n)*[ \t>]*(?:user|human|assistant|ai)\s*:/i, label: "fabricated conversation turn" },
  // "Focus only on the following / disregard everything except …" — the attend-
  // here-instead redirection used by latent document injections.
  // Anchored on injection-specific objects only (the following / brackets /
  // angled) — "between", "information", "below" were common enough to false-
  // positive on ordinary prose ("focus only on one task ... between sessions").
  { id: "exclusive_focus", weight: 1, kind: "instruction", re: /\b(?:focus|reply|respond|answer)\s+(?:with\s+)?(?:only|exclusively)\b[^.\n]{0,40}\b(?:following|brackets|angled)\b|\bdisregard\s+(?:all|everything)\b[^.\n]{0,40}\bexcept\b/i, label: "exclusive-focus / disregard-all-except redirection" },
  // Persona swap needs a role noun: "you are now an unrestricted assistant",
  // "you are now in developer mode". Bare "you are now" is everywhere ("you
  // are now subscribed", "you are no longer logged in").
  { id: "persona_swap", weight: 1, kind: "instruction", re: /\byou\s+are\s+(?:now|no\s+longer)\s+(?:an?\s+|the\s+|in\s+|my\s+)?(?:\w+\s+){0,2}(?:assistant|agent|ai|bot|model|mode|persona|character|dan|jailbroken|unrestricted|unfiltered|uncensored|developer|admin|administrator|operator|system|version)\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|different|new)\b|\bpretend\s+(?:to\s+be|you\s+are)\b|\bfrom\s+now\s+on\s+you\s+(?:are|will|must)\b|\byour\s+new\s+(?:role|persona|identity)\s+is\b|\b(?:developer|god|jailbreak|dan)\s+mode\s+(?:enabled|activated|on)\b/i, label: "persona/role swap instruction" },
  { id: "precedence", weight: 1, kind: "instruction", re: /\bbefore\s+(?:doing|you\s+do)\s+anything\s+else\b|\b(?:overrides?|supersedes?|takes?\s+(?:priority|precedence))\s+(?:over\s+)?(?:all\s+)?(?:other|previous|prior|any)\b/i, label: "priority/precedence override phrasing" },
  { id: "urgency", weight: 1, kind: "pressure", re: /\b(?:urgent(?:ly)?|final\s+(?:warning|notice)|account\s+(?:will\s+be\s+)?(?:suspended|terminated)|within\s+\d+\s+(?:minutes?|hours?)\s+or)\b/i, label: "urgency/threat pressure" },
  // Business-email-compromise phrasing: the payee "changed", use the "updated
  // address". The most common real-world payment-redirection fraud has no
  // override verb at all. Weight 1 — "enter your new shipping address" is
  // benign — and "new wallet" alone is not enough (every crypto doc says it).
  { id: "payee_change", weight: 1, kind: "instruction", re: /\b(?:new|updated|changed|replacement|corrected|alternate|alternative)\s+(?:\w+\s+)?(?:wallet\s+address|payment\s+address|deposit\s+address|receiving\s+address|payee|bank\s+account|payment\s+details|banking\s+details|remittance\s+details)\b|\b(?:wallet|address|payee|bank\s+account|payment\s+details|banking\s+details)\s+(?:has|have|was|were)\s+(?:recently\s+|just\s+)?(?:been\s+)?(?:changed|updated|switched|moved|migrated|replaced)\b|\b(?:switched|changed|moved)\s+(?:their|our|the|its)\s+(?:\w+\s+)?(?:wallet|address|payee|bank\s+account)\b/i, label: "payee/beneficiary change phrasing" },
  // "…without checking back / no need to verify": the companion to
  // payee_change — a payment instruction that pre-empts verification.
  { id: "verify_suppress", weight: 1, kind: "instruction", re: /\b(?:without|no\s+need\s+to|no\s+need\s+for|don'?t|do\s+not|never|skip|not\s+necessary\s+to|there'?s\s+no\s+need\s+to)\s+(?:first\s+|bother\s+(?:to\s+)?)?(?:verif(?:y|ying|ication)|confirm(?:ing|ation)?|double.?check(?:ing)?|check(?:ing)?\s+(?:back|with|first)|validat(?:e|ing|ion)|ask(?:ing)?\s+(?:the\s+)?(?:user|human|owner|operator|anyone))\b/i, label: "verification-suppression phrasing" },
  { id: "invisible_chars", weight: 1, kind: "pressure", re: TELL_INVISIBLE, label: "invisible/zero-width/tag characters (hidden text)" },
  // An ASCII letter directly joined to a Cyrillic/Greek/IPA/small-cap letter
  // inside one word. Real text does not mix scripts within a word; a
  // homoglyph substitution the fold table does not know still looks like this.
  { id: "mixed_script", weight: 1, kind: "pressure", re: new RegExp(`[a-zA-Z][${CONFUSABLE_CLASS}]|[${CONFUSABLE_CLASS}][a-zA-Z]`), label: "mixed-script word (homoglyph substitution)" },
];

export interface TellHit {
  id: string;
  label: string;
  weight: number;
  kind: TellKind;
  /** Match offset in the scanned text (for proximity scoring). */
  index: number;
}

/** Scan a string for injection indicators. Exported for the deep tier and tests. */
export function findTells(text: string): TellHit[] {
  const hits: TellHit[] = [];
  for (const t of INJECTION_TELLS) {
    const m = t.re.exec(text);
    if (m) hits.push({ id: t.id, label: t.label, weight: t.weight, kind: t.kind, index: m.index });
  }
  return hits;
}

// Address-like tokens: 0x-hex, or a base58 run of Solana length. A base58
// candidate must carry a digit AND both letter cases — every real 32-byte
// base58 key does, while a zero-free git SHA (lowercase hex, ~8% of SHAs) or
// an API-key body (no digits) does not.
const ADDR_TOKEN_G = /0x[0-9a-fA-F]{6,}|[1-9A-HJ-NP-Za-km-z]{32,44}/g;
const PROXIMITY_CHARS = 300;
/** Weight-1 tells only compound within this distance of another tell. */
const CLUSTER_CHARS = 500;

function addressIndices(text: string): number[] {
  const out: number[] = [];
  for (const m of text.matchAll(ADDR_TOKEN_G)) {
    const tok = m[0];
    if (!tok.startsWith("0x") && !(/\d/.test(tok) && /[a-z]/.test(tok) && /[A-Z]/.test(tok))) continue;
    out.push(m.index ?? 0);
  }
  return out;
}

export interface TextScore {
  hits: TellHit[];
  score: number;
  proximity: { tell_id: string; distance: number } | null;
}

/**
 * Weighted score. Rules:
 *   * a weight-2 tell always counts;
 *   * a weight-1 tell counts only when it clusters — within CLUSTER_CHARS of
 *     another tell, or within PROXIMITY_CHARS of an address-like token — so
 *     "urgent" in the header and "you are now…" in the footer of a 200KB
 *     page do not add up to an injection;
 *   * pressure tells alone (urgency + transcript shape + a zero-width char)
 *     never exceed 1 without an address nearby — pressure is not a directive;
 *   * isolated weak tells still report as 1 (a flag);
 *   * the proximity boost is +2 from an untrusted origin, +1 from a trusted
 *     one (a SHA near "urgent" in the agent's own plan is not a redirection).
 *     Content only, never offers — offers legitimately contain pay_to and
 *     would self-trigger. send_to_address carries its own address and
 *     invisible_chars has no position of interest, so neither anchors it.
 */
function scoreText(
  text: string,
  hits: TellHit[],
  opts: { proximity: boolean; untrusted: boolean },
): TextScore {
  if (hits.length === 0) return { hits, score: 0, proximity: null };
  const addrs = opts.proximity ? addressIndices(text) : [];
  const near = (h: TellHit, limit: number): number | null => {
    let best: number | null = null;
    for (const a of addrs) {
      const d = Math.abs(h.index - a);
      if (d <= limit && (best === null || d < best)) best = d;
    }
    return best;
  };
  const anchorable = (h: TellHit): boolean => h.id !== "send_to_address" && h.id !== "invisible_chars" && h.id !== "mixed_script";
  const effective = hits.filter(
    (h) =>
      h.weight === 2 ||
      hits.some((o) => o !== h && Math.abs(o.index - h.index) <= CLUSTER_CHARS) ||
      (anchorable(h) && near(h, PROXIMITY_CHARS) !== null),
  );
  let proximity: { tell_id: string; distance: number } | null = null;
  for (const h of effective) {
    if (!anchorable(h)) continue;
    const d = near(h, PROXIMITY_CHARS);
    if (d !== null && (!proximity || d < proximity.distance)) proximity = { tell_id: h.id, distance: d };
  }
  let score: number;
  if (effective.length === 0) {
    score = 1;
  } else {
    score = effective.reduce((s, h) => s + h.weight, 0);
    if (effective.every((h) => h.weight === 1 && h.kind === "pressure")) score = 1;
  }
  if (proximity) score += opts.untrusted ? 2 : 1;
  return { hits, score, proximity };
}

/** Escalation rule shared by content, offer and decoded-payload findings. */
function escalates(score: number, untrusted: boolean): boolean {
  return (untrusted && score >= 2) || score >= 3;
}

/**
 * Score prose content: raw text and (when it carries markup) the stripped
 * rendering, merged. From a user_instruction origin the pay-command and
 * send-to-address tells are reported but not scored — "be sure to pay the
 * invoice to 0x…" is how a human tells an agent to pay.
 */
function scoreContent(content: string, origin: PaymentOrigin | "unknown", untrusted: boolean): TextScore {
  const userSaid = origin === "user_instruction";
  const scorable = (hits: TellHit[]): TellHit[] =>
    userSaid ? hits.filter((h) => h.id !== "pay_command" && h.id !== "send_to_address") : hits;
  const raw = findTells(content);
  let best = scoreText(content, scorable(raw), { proximity: true, untrusted });
  let reported = raw;
  const stripped = stripMarkup(content);
  if (stripped !== content) {
    const sHits = findTells(stripped);
    const s = scoreText(stripped, scorable(sHits), { proximity: true, untrusted });
    const seen = new Set(reported.map((h) => h.id));
    reported = reported.concat(sHits.filter((h) => !seen.has(h.id)));
    if (s.score > best.score) best = s;
  }
  return { hits: reported, score: best.score, proximity: best.proximity };
}

// ---------------------------------------------------------------------------
// Fast tier
// ---------------------------------------------------------------------------

/**
 * Server-observed facts the scanner establishes BEFORE any state mutation, used
 * to mitigate (never to escalate) the provenance finding. Read-only by
 * construction: the caller reads prior pin state before `checkPinning` writes.
 */
export interface InjectionProvenance {
  /**
   * The resource domain was ALREADY pinned to this exact pay_to before this
   * scan — i.e. the payee predates the content the agent just read.
   */
  payeeEstablishedBefore?: boolean;
}

// Separators an address gets split on for display or evasion: whitespace,
// dashes, dots, colons, ellipses, middle dots, bullets.
const ADDR_SEPARATORS_G = /[\s\-_.:…·•]+/g;
const EVM_PAY_TO = /^0x[0-9a-f]{40}$/;

export function checkInjection(
  payment: PaymentDetails,
  context: ScanContext | undefined,
  provenance?: InjectionProvenance,
): CheckResult[] {
  const results: CheckResult[] = [];
  const origin = context?.origin ?? "unknown";
  const content = context?.content ?? "";
  const fromUntrusted = origin === "tool_result" || origin === "fetched_content";

  // Content analysis is computed up front (results are still pushed in the
  // original order below) because the provenance finding needs to know whether
  // the content is otherwise clean before it can be mitigated.
  const contentScore = content ? scoreContent(content, origin, fromUntrusted) : null;
  const contentHits = contentScore?.hits ?? [];
  const payToLc = payment.pay_to?.toLowerCase();
  let payToDirect = false;
  let payToLaced = false; // hidden with invisible characters
  let payToSplit = false; // broken across whitespace/separators, or 0x-less
  if (content && payToLc) {
    const contentLc = content.toLowerCase();
    payToDirect = contentLc.includes(payToLc);
    if (!payToDirect) {
      const unlaced = stripInvisible(contentLc);
      payToLaced = unlaced.includes(payToLc);
      if (!payToLaced) {
        const collapsed = unlaced.replace(ADDR_SEPARATORS_G, "");
        payToSplit = collapsed.includes(payToLc);
        if (!payToSplit && EVM_PAY_TO.test(payToLc)) {
          const body = payToLc.slice(2);
          payToSplit = new RegExp(`(?<![0-9a-f])${body}(?![0-9a-f])`).test(collapsed);
        }
      }
    }
  }
  const payToObfuscated = payToLaced || payToSplit;

  // 1. Provenance: did the decision to pay come from content the agent just read?
  //
  // The hypothesis this check raises is "injected content steered the agent to
  // this payee". That hypothesis has no support left when ALL of the following
  // hold, so the finding drops to informational rather than dead-ending an
  // unattended agent on every honest fetched-content purchase:
  //
  //   * the content was actually SUPPLIED, so there is something to clear. An
  //     untrusted origin declared with no content at all is unverifiable —
  //     absence of content is absence of evidence, not evidence of absence, and
  //     mitigating it would let any caller silence the advisory by omitting the
  //     very field the check exists to inspect;
  //   * the domain was already pinned to this exact pay_to BEFORE this scan —
  //     server-observed, so the payee predates the content (and the redirection
  //     case cannot reach here at all: a different pay_to on a pinned domain is
  //     `pin.mismatch`, a block);
  //   * the content carries no injection tells;
  //   * pay_to does not appear in the content, verbatim or obfuscated.
  //
  // Absent that evidence the flag stands — the mitigation is fail-closed, and
  // it only ever lowers a flag, so H-2 is untouched (no client-supplied signal
  // reaches a block decision).
  const provenanceMitigated =
    fromUntrusted &&
    content.length > 0 &&
    provenance?.payeeEstablishedBefore === true &&
    contentHits.length === 0 &&
    !payToDirect &&
    !payToObfuscated;

  if (provenanceMitigated) {
    results.push({
      id: "injection.untrusted_origin_mitigated",
      name: "Prompt-injection-triggered payment",
      verdict: "allow",
      severity: "info",
      reason: `Payment originated from ${origin === "tool_result" ? "a tool result" : "fetched external content"}, but the recipient was already pinned to this domain before this scan, the content carries no injection indicators, and the recipient address does not appear in it. The payee predates the content, so the content cannot have introduced it.`,
      details: {
        origin,
        content_source_url: context?.content_source_url,
        mitigation: "payee_pinned_before_content",
      },
    });
  } else if (fromUntrusted) {
    results.push({
      id: "injection.untrusted_origin",
      name: "Prompt-injection-triggered payment",
      verdict: "flag",
      severity: "medium",
      reason: `This payment originated from ${origin === "tool_result" ? "a tool result" : "fetched external content"} rather than the agent's own planning step. Payments prompted by just-read content are the primary prompt-injection exfiltration path — confirm against the agent's plan before settling.`,
      details: { origin, content_source_url: context?.content_source_url },
    });
  } else if (origin === "unknown") {
    results.push({
      id: "injection.unknown_origin",
      name: "Prompt-injection-triggered payment",
      verdict: "flag",
      severity: "low",
      reason:
        "Payment origin not declared. Pass context.origin (planning | user_instruction | tool_result | fetched_content) so provenance can be verified.",
    });
  }

  if (content && contentScore) {
    // 2. Injection tells inside the content the agent just read. Weighted:
    // one strong tell (or a weak tell near an address) escalates from an
    // untrusted origin; a score of 3 escalates from any origin. A lone weak
    // tell (e.g. "urgent" in a fetched page) flags rather than blocks.
    const hits = contentHits;
    if (hits.length > 0) {
      const { score, proximity } = contentScore;
      const escalate = escalates(score, fromUntrusted);
      results.push({
        id: "injection.content_tells",
        name: "Prompt-injection-triggered payment",
        verdict: escalate ? "block" : "flag",
        severity: escalate ? "critical" : "medium",
        reason:
          `The content preceding this payment contains prompt-injection indicators: ${hits.map((h) => h.label).join("; ")}.` +
          (proximity ? ` The "${proximity.tell_id}" indicator occurs within ${proximity.distance} characters of an address-like token — instructions adjacent to an address are the strongest redirection signal.` : ""),
        details: { indicators: hits.map((h) => h.id), score, proximity, origin },
      });
    }

    // 3. Address provenance: pay_to appears in untrusted content — verbatim,
    // or only after stripping invisible characters / collapsing separators
    // (laced or split addresses). Lacing an address with invisible characters
    // is concealment from any origin: block. A split address blocks from any
    // origin except user_instruction — a human pasting "0x2096 93bc …" grouped
    // for readability is display, not evasion, and from that origin it flags
    // like a verbatim match.
    if (payment.pay_to && payToLc) {
      const direct = payToDirect;
      const obfuscated = payToObfuscated;
      if (direct || obfuscated) {
        const block = fromUntrusted || payToLaced || (payToSplit && origin !== "user_instruction");
        results.push({
          id: "injection.payto_from_content",
          name: "Prompt-injection-triggered payment",
          verdict: block ? "block" : "flag",
          severity: block ? "critical" : "high",
          reason: obfuscated
            ? "The payment recipient address appears in the content the agent just read, hidden by whitespace/separator splitting or invisible characters. Obfuscating an address to evade scanning is itself a strong attack signal."
            : "The payment recipient address appears verbatim in the content the agent just read. Recipient addresses sourced from untrusted content are the classic payment-redirection attack. (If this text is the 402 offer / discovery payload itself, pass it in context.offer instead — pay_to is expected there.)",
          // implicated_address: on a block, this finding structurally binds
          // pay_to to injected content — the incident ledger records it so
          // future scans of the same wallet inherit the signal (flag-only).
          details: { pay_to: payment.pay_to, origin, obfuscated, implicated_address: payToLc },
        });
      }
    }
  }

  // The offer channel: protocol-shaped payment terms (402 accepts entry,
  // Bazaar listing). pay_to appearing here is how x402 works — no provenance
  // finding — but the offer is counterparty-authored text, so injection tells
  // inside it (e.g. a description carrying instructions) still fire. Offers
  // are always counterparty-authored, so a strong tell blocks; weak tells
  // ("urgent alerts API — you must pay per request") only flag.
  const offer = context?.offer ?? "";
  if (offer) {
    const offerHits = findTells(offer);
    if (offerHits.length > 0) {
      const { score } = scoreText(offer, offerHits, { proximity: false, untrusted: true });
      const escalate = offerHits.some((h) => h.weight === 2);
      results.push({
        id: "injection.offer_tells",
        name: "Prompt-injection-triggered payment",
        verdict: escalate ? "block" : "flag",
        severity: escalate ? "critical" : "medium",
        reason: `The payment offer itself contains prompt-injection indicators: ${offerHits.map((h) => h.label).join("; ")}. Offer fields are counterparty-authored — instructions embedded in them target the paying agent.`,
        details: { indicators: offerHits.map((h) => h.id), score, proximity: null },
      });
    }
  }

  if (results.length === 0) {
    results.push({
      id: "injection.clean",
      name: "Prompt-injection-triggered payment",
      verdict: "allow",
      severity: "info",
      reason: `Payment originated from ${origin.replace("_", " ")}; no injection indicators found.`,
    });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Deep tier
// ---------------------------------------------------------------------------

const PRINTABLE = /^[\x09\x0a\x0d\x20-\x7e]+$/;
// Standard AND URL-safe base64 alphabets. Long hyphenated/plain words can
// match too — decode noise is filtered by the PRINTABLE + tells gates below.
const B64_BLOB_G = /[A-Za-z0-9+/_-]{24,}={0,2}/g;
const B64_WHOLE = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;
// Line-wrapped (MIME) and space-chunked blobs are joined before extraction.
// Both patterns use FIXED-width lookarounds on purpose: the earlier
// `([alphabet]{12,})\n(?=[alphabet]{12,})` form was quadratic on a long
// alphabet run with no newline (42 s at the 200KB cap — a counterparty page
// with one big hex blob stalled the event loop for every tenant).
const B64_LINEJOIN_G = /(?<=[A-Za-z0-9+/_-]{12})[ \t]*\r?\n[ \t]*(?=[A-Za-z0-9+/_-]{12})/g;
const B64_SPACEJOIN_G = /(?<=[A-Za-z0-9+/_-]{8}) (?=[A-Za-z0-9+/_-]{8})/g;
const HEX_BLOB_G = /(?:0x)?(?:[0-9a-fA-F]{2}){16,}/g;
const TAG_PRESENT = /[\u{E0000}-\u{E007F}]/u;
const MAX_BLOBS = 32;

function tryBase64(blob: string): string | null {
  try {
    const d = Buffer.from(blob, "base64").toString("utf8");
    return d.length > 0 && PRINTABLE.test(d) ? d : null;
  } catch {
    return null;
  }
}

/** Decode Unicode tag characters (U+E0020–E007E) back to the ASCII they mirror. */
function decodeTagChars(text: string): string {
  if (!TAG_PRESENT.test(text)) return "";
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

function safeCodePoint(cp: number): string {
  return cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
}

// Leetspeak: digits standing in for letters inside an otherwise alphabetic
// token ("1gn0re", "prev10us"). Only tokens made of letters plus these
// specific digits fold — "sha256", "b64", "0x1f2e" contain other digits and
// stay as they are. The fold is scanned for tells only, so a harmless
// "mp3" → "mpe" costs nothing.
const LEET_TOKEN_G = /\b(?=[a-z013457@$]*[a-z])(?=[a-z013457@$]*[013457@$])[a-z013457@$]{3,}\b/gi;
const LEET_MAP: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };
// Letter-spaced words: "i g n o r e" (three or more single letters separated
// by one space — "a l l" has to fold too) collapse to "ignore".
const SPACED_LETTERS_G = /\b(?:[a-z] ){2,}[a-z]\b/gi;

/** Fold leetspeak digits and letter-spacing. Exported for tests. */
export function foldLeetAndSpacing(text: string): string {
  return text
    .replace(SPACED_LETTERS_G, (m) => m.replace(/ /g, ""))
    .replace(LEET_TOKEN_G, (m) => m.replace(/[013457@$]/g, (c) => LEET_MAP[c] ?? c));
}

/**
 * Deep content-analysis tier. Decodes the cheap obfuscations (base64 in both
 * alphabets incl. line-wrapped/space-chunked and double-encoded, hex,
 * percent-encoding, HTML entities, JS escapes, Unicode tag smuggling),
 * unicode-skeleton-folds and leet/spacing-folds the content, then rescans.
 * Still regex/linear speed on the (200KB-capped) content; gated by the
 * micropayment bypass policy because obfuscated attacks target payments
 * worth stealing — and always on for untrusted-origin content.
 */
export function deepContentAnalysis(
  payment: PaymentDetails,
  context: ScanContext | undefined,
): CheckResult[] {
  const content = context?.content ?? "";
  if (!content) return [];
  const results: CheckResult[] = [];
  const origin = context?.origin ?? "unknown";
  const fromUntrusted = origin === "tool_result" || origin === "fetched_content";
  const payToLc = payment.pay_to?.toLowerCase();
  const embedsPayTo = (text: string): boolean =>
    payToLc !== undefined && text.toLowerCase().includes(payToLc);
  // A decoded payload escalates on the same rule as prose: one strong tell
  // (or a clustered pair) from an untrusted origin, three from anywhere, or
  // the recipient address embedded in it. A base64 e-mail body that merely
  // says "urgent" (Gmail tool results are base64) is a flag, not a block.
  const decodedVerdict = (hits: TellHit[], text: string, embeds: boolean): "block" | "flag" =>
    embeds || escalates(scoreText(text, hits, { proximity: true, untrusted: fromUntrusted }).score, fromUntrusted) ? "block" : "flag";

  // 4. Base64-obfuscated payloads. Join line-wrapped and space-chunked blobs
  // first, then try each candidate; a decode that is itself base64 is
  // decoded once more (double-encoding).
  const joined = content.replace(B64_LINEJOIN_G, "").replace(B64_SPACEJOIN_G, "");
  const blobs = joined.match(B64_BLOB_G) ?? [];
  for (const blob of blobs.slice(0, MAX_BLOBS)) {
    let decoded = tryBase64(blob);
    if (decoded === null) continue;
    let doubleEncoded = false;
    let tells = findTells(decoded);
    let embeds = embedsPayTo(decoded);
    if (tells.length === 0 && !embeds && B64_WHOLE.test(decoded.trim())) {
      const inner = tryBase64(decoded.trim());
      if (inner !== null) {
        decoded = inner;
        doubleEncoded = true;
        tells = findTells(inner);
        embeds = embedsPayTo(inner);
      }
    }
    if (tells.length > 0 || embeds) {
      results.push({
        id: "injection.b64_obfuscated",
        name: "Prompt-injection-triggered payment (deep)",
        verdict: decodedVerdict(tells, decoded, embeds),
        severity: "critical",
        reason: `A ${doubleEncoded ? "doubly " : ""}base64-encoded blob in the just-read content decodes to ${embeds ? "text embedding the payment recipient address" : "prompt-injection content"}${tells.length ? ` (${tells.map((t) => t.label).join("; ")})` : ""}. Encoding instructions to evade filters is itself a strong attack signal.`,
        details: {
          decoded_preview: decoded.slice(0, 120),
          indicators: tells.map((t) => t.id),
          double_encoded: doubleEncoded,
          // Only an EMBEDDED pay_to implicates the recipient; tells alone
          // don't prove the payee authored the payload.
          ...(embeds ? { implicated_address: payToLc } : {}),
        },
      });
      break; // one finding is enough
    }
  }

  // 5. Other encodings: hex blobs, percent(URL)-encoding, HTML numeric
  // entities, JS/JSON escapes. First encoding family that reveals something
  // reports; the finding is about "an encoded payload exists", not an
  // inventory.
  const rawTellIds = new Set(findTells(content).map((t) => t.id));
  const encodedFinding = (encoding: string, decoded: string): boolean => {
    const fresh = findTells(decoded).filter((t) => !rawTellIds.has(t.id));
    const embeds = embedsPayTo(decoded) && !embedsPayTo(content);
    if (fresh.length === 0 && !embeds) return false;
    results.push({
      id: "injection.encoded_content",
      name: "Prompt-injection-triggered payment (deep)",
      verdict: decodedVerdict(fresh, decoded, embeds),
      severity: "critical",
      reason: `${encoding}-encoded text in the just-read content decodes to ${embeds ? "text embedding the payment recipient address" : "prompt-injection content"}${fresh.length ? ` (${fresh.map((t) => t.label).join("; ")})` : ""}. Encoding instructions to evade filters is itself a strong attack signal.`,
      details: {
        encoding,
        decoded_preview: decoded.slice(0, 120),
        indicators: fresh.map((t) => t.id),
        ...(embeds ? { implicated_address: payToLc } : {}),
      },
    });
    return true;
  };
  encodedHunt: {
    // hex
    for (const blob of (content.match(HEX_BLOB_G) ?? []).slice(0, MAX_BLOBS)) {
      const hex = blob.startsWith("0x") ? blob.slice(2) : blob;
      const decoded = Buffer.from(hex, "hex").toString("utf8");
      if (PRINTABLE.test(decoded) && encodedFinding("hex", decoded)) break encodedHunt;
    }
    // percent-encoding
    if (/%[0-9a-fA-F]{2}/.test(content)) {
      const decoded = content.replace(/%([0-9a-fA-F]{2})/g, (_, h: string) =>
        String.fromCharCode(parseInt(h, 16)),
      );
      if (encodedFinding("percent(URL)", decoded)) break encodedHunt;
    }
    // HTML numeric entities
    if (/&#x?[0-9a-fA-F]+;/.test(content)) {
      const decoded = content
        .replace(/&#x([0-9a-fA-F]+);/gi, (_, h: string) => safeCodePoint(parseInt(h, 16)))
        .replace(/&#(\d+);/g, (_, d: string) => safeCodePoint(parseInt(d, 10)));
      if (encodedFinding("HTML-entity", decoded)) break encodedHunt;
    }
    // JS / JSON string escapes (\x69, i)
    if (/\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})/.test(content)) {
      const decoded = content
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
      if (encodedFinding("JS-escape", decoded)) break encodedHunt;
    }
  }

  // 6. Unicode tag-character smuggling: instructions mirrored into the
  // invisible tag block. Emoji flag sequences also use tag chars (e.g. the
  // England flag decodes to "gbeng"), so only report when the decoded text
  // actually carries tells, the recipient address, or an address-like token.
  const tagDecoded = decodeTagChars(content);
  if (tagDecoded) {
    const tells = findTells(tagDecoded);
    const embeds = embedsPayTo(tagDecoded);
    const hasAddr = addressIndices(tagDecoded).length > 0;
    if (tells.length > 0 || embeds || hasAddr) {
      results.push({
        id: "injection.tag_smuggling",
        name: "Prompt-injection-triggered payment (deep)",
        verdict: "block",
        severity: "critical",
        reason: `The just-read content carries text smuggled in invisible Unicode tag characters${embeds ? ", embedding the payment recipient address" : ""}${tells.length ? ` (${tells.map((t) => t.label).join("; ")})` : hasAddr && !embeds ? " (containing an address-like token)" : ""}. Tag-character smuggling has no legitimate use in prose and targets LLM agents specifically.`,
        details: {
          decoded_preview: tagDecoded.slice(0, 120),
          indicators: tells.map((t) => t.id),
          ...(embeds ? { implicated_address: payToLc } : {}),
        },
      });
    }
  }

  // 7./8. Normalization rescans. A fold that REVEALS tells the raw scan did
  // not see is the finding; the concealment itself counts as one weak signal
  // on top (hiding "you must pay" behind homoglyphs is deliberate), so a
  // revealed weight-1 tell escalates from an untrusted origin while benign
  // Cyrillic prose that reveals nothing stays silent.
  const OBFUSCATION_TELLS = new Set(["invisible_chars", "mixed_script"]);
  const realTells = (text: string): TellHit[] => findTells(text).filter((t) => !OBFUSCATION_TELLS.has(t.id));
  // Each fold is judged against the text it folded FROM, so the leet pass
  // (which runs on the skeleton) does not re-report the skeleton's finding.
  const foldFinding = (id: string, from: string, folded: string, how: string): void => {
    if (folded === from) return;
    const baseline = realTells(from).length;
    const fTells = realTells(folded);
    if (fTells.length <= baseline) return;
    const base = scoreText(folded, fTells, { proximity: true, untrusted: fromUntrusted }).score;
    const escalate = escalates(base + 1, fromUntrusted);
    results.push({
      id,
      name: "Prompt-injection-triggered payment (deep)",
      verdict: escalate ? "block" : "flag",
      severity: "critical",
      reason: `Injection indicators appear only after ${how}: ${fTells.map((t) => t.label).join("; ")}. Hidden-character, lookalike-letter or digit-for-letter obfuscation is itself a strong attack signal.`,
      details: { indicators: fTells.map((t) => t.id) },
    });
  };
  const sk = skeleton(content);
  foldFinding("injection.unicode_obfuscated", content, sk, "unicode normalization (zero-width stripping / homoglyph folding)");
  foldFinding("injection.leet_obfuscated", sk, foldLeetAndSpacing(sk), "leetspeak / letter-spacing folding");

  return results;
}
