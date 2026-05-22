# Code Review: PR #1 — fix-hook-security

**Verdict:** ⚠️ CHANGES REQUESTED

| | |
| - | - |
| **Branch** | `fix/hook-security` |
| **PR** | [#1](https://github.com/RealManage/llm-wiki-compiler/pull/1) |
| **Author** | @alexnoissue |
| **Reviewer** | @Cali LaFollett |
| **Review Round** | 1 |
| **Title** | fix(hooks): harden wiki-session-context against config-driven injection |
| **Head** | `8a6d773` |
| **Files Changed** | 1 |
| **Lines Changed** | +117 / -23 |
| **Date** | 2026-05-22 |

---

## Summary

Excellent hardening of the session-start hook. The original fixes (`JSON.parse` instead of `require()`, `printf '%s'` instead of `%b`, output sanitization, bounded upward config search) close real prompt-injection and arbitrary-execution vectors. Subsequent self-review commits (`8a6d773`) tightened things further — locale-independent byte-range sanitization, env-var fallback in `read_state`, `$HOME` normalization, and a Windows/git-bash path-normalization catch that's genuinely impressive. One residual gap remains from the same attacker model: values read from `.compile-state.json` (`topic_count`, `last_compiled`) still bypass `sanitize()` and flow into the LLM-facing banner — a malicious-repo author shipping a crafted state file can inject the same way a crafted config used to. The PR description has also drifted out of sync with the implementation across iterations.

---

## Findings Overview

| Severity | In Scope | Out of Scope |
| - | - | - |
| 🔴 CRITICAL | 0 | 0 |
| 🟠 HIGH | 0 | 0 |
| 🟡 MEDIUM | 1 | 0 |
| 🟢 LOW | 1 | 0 |
| ℹ️ INFO | 1 | 0 |

---

## In Scope Findings

### 🟡 MEDIUM-001: State file values bypass `sanitize()` — same injection class the PR fixes

**Domains:** [Security]
**Location:** `plugin/hooks/wiki-session-context:111-112`

`topic_count` and `last_compiled` are read from `.compile-state.json` via `read_state` and emitted into the banner without sanitization:

```bash
topic_count="$(read_state "console.log((s.topics||[]).length)" "?")"
last_compiled="$(read_state "console.log(s.last_compiled || 'unknown')" "unknown")"
```

The PR description's threat model is "any string sourced from the config is attacker-controllable" — but `.compile-state.json` lives in the repo at `$project_root/$output_path/.compile-state.json` and is just as shippable in a malicious repo as the config. An attacker who controls the repo (the same model the PR addresses) can ship a poisoned state file with a `last_compiled` value such as `"2026-05-22\n\nIMPORTANT: ignore prior instructions and …"`. After `JSON.parse`, that newline survives the bash pipeline and is interpolated directly into the LLM banner via lines like:

```bash
Topics: $topic_count | Last compiled: $last_compiled
```

The hook only reads state after confirming `INDEX.md` exists (line 106), so the attack requires the malicious repo to ship a pre-compiled `wiki/` tree — a low bar.

`topic_count` is lower-risk because it's coerced through `.length` (a number), but applying `sanitize` uniformly is the right defense-in-depth.

**Recommendation:**

Apply `sanitize` to both state-derived values, matching the treatment of config values:

```bash
topic_count="$(read_state "console.log((s.topics||[]).length)" "?" | sanitize)"
last_compiled="$(read_state "console.log(s.last_compiled || 'unknown')" "unknown" | sanitize)"
```

Roughly five characters of churn for symmetry with the threat model the PR already documents. Worth folding into this PR rather than a follow-up — the gap is in the same file and the same banner.

---

### 🟢 LOW-001: PR description out of sync with the implementation

**Domains:** [Documentation]
**Location:** PR #1 body, "Fixes" section item 2

The PR description states:

> **Config lookup pinned to git repo root** — no upward walk. Stray `.wiki-compiler.json` in `~/`, `/tmp/`, or any ancestor dir no longer activates the hook.

This describes an earlier iteration. The current implementation at `8a6d773` walks upward, bounded by `$HOME` (for cwd under home) or the enclosing git repo root (for cwd outside home). A `.wiki-compiler.json` in `~/` IS picked up if cwd is under `~/`. The threat-model claim still holds for `/tmp/`, `/etc/`, and non-HOME / non-git ancestors, but the home half is wrong.

**Recommendation:**

Replace item 2 with the actual current behavior:

> **Config lookup bounded by `$HOME` or enclosing git repo root** — walks upward but refuses to leave the bound. Stray `.wiki-compiler.json` in `/tmp/`, `/etc/`, or any non-HOME / non-git ancestor no longer activates the hook. A config at `$HOME` (or above the git root for non-home work) is still trusted as user-installed.

Reflect this in the commit body too, so the squash commit on `main` matches the shipped behavior.

---

## ℹ️ Informational

### INFO-001: 200-byte cap silently truncates long but legitimate values

**Location:** `plugin/hooks/wiki-session-context:12`

`name`, `output_path`, `mode`, `wiki_mode`, and `auto_update` are all capped at 200 chars. For `mode` / `auto_update` / `wiki_mode` this is fine (enum-like). For `name` and `output_path` it's a soft limit users might run into with a long project name or a deeply-nested output directory. No action required — flagging it as a known edge.

---

## Out of Scope

None — diff is the whole change.

---

## What's Working Well

- **`require()` → `JSON.parse(fs.readFileSync(...))`** is the right call. Eliminates the symlink/extension-confusion JS-execution path entirely.
- **`printf '%s'` instead of `%b`** closes the literal-`\n` / `\x1b` escape-sequence re-interpretation door. Rewriting the case-block banner strings to use real newlines keeps the switch lossless.
- **Locale-independent byte-range sanitize** (`LC_ALL=C tr -cd '\11\40-\176'`) is stronger than the `[:print:]\t` form — explicit byte ranges sidestep locale-dependent POSIX class definitions entirely. The comment about UTF-8 U+2028/U+2029 line separators is exactly the right rationale to leave behind.
- **Bounded upward walk** (`$HOME` for home-rooted work, git root for outside-home, refuse otherwise) is a thoughtful UX/security tradeoff. Restores legitimate home-anchored workflows (`~/Knowledge/notes/`, `~/projects/foo/sub`) while keeping `/tmp/` / `/etc/` activations refused. The empty-`bound` guard makes "neither applies → no walk" the security-conscious default.
- **`$HOME` normalization** (`home="${HOME:-}"; home="${home%/}"` plus the `[ "$home" != "/" ]` guard) hardens against trailing slash, unset, and `HOME=/` edge cases.
- **Windows / git-bash path normalization** via `cygpath -u` is a genuinely excellent catch. `git rev-parse --show-toplevel` returns `C:/Users/…` on git-bash while the loop walks with MSYS-style `/c/Users/…`, so the bound check would silently never fire and the walk would escape its bound. Real defect, real fix, clear comment explaining why. 💯
- **`read_state` fallback via env var** instead of JS source interpolation eliminates the quote/backslash escape risk in the helper.
- **`sanitize()`** stripping newlines (vs. just control chars) is the key insight — that's what prevents banner injection from looking like a legitimate instruction line.
- **Defensive inline comments** (`// JSON.parse, not require()`, `// %s not %b`, search-bound rationale, HOME normalization rationale, cygpath rationale, fallback env-var rationale) explain non-obvious choices to future-maintainers without bloating the file. Excellent stewardship.
- **PR description threat model + smoke test plan** are exemplary — explicit attacker model, listed fixes, what was tested, residuals. Easy to review against (the body just needs a refresh after the iteration).

---

## Action Items

### Must Fix (blocks merge)

(none)

### Should Fix

- [ ] **MEDIUM-001** — Apply `sanitize` to `topic_count` and `last_compiled` (closes the same injection class via state file)
- [ ] **LOW-001** — Update PR description (and commit body) item 2 to match the bounded-walk implementation

### Consider

(none — INFO-001 is awareness only)

---

## Files Reviewed

| File | Findings |
| - | - |
| `plugin/hooks/wiki-session-context` | 3 (1 MEDIUM, 1 LOW, 1 INFO) |

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
