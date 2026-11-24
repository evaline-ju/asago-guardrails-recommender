# Feature: conversation-scoped rails (multi-turn attacks → multi-turn recommendations)

## Summary

The recommender today can only recommend **message-scoped** rails: every rail card detects signals in a single utterance, and tagging, scoring and testing all operate on `adversarial_text` alone — even though `AttackRecord` already carries the full conversation (`messages`, `attack_turn_index`, loaded from the upstream garak transcripts by `attacks.py`). Testing sends only the attack turn to `/v1/checks`, which itself evaluates each message independently. Multi-turn attack patterns — gradual jailbreaks, topic drift, distributed PII extraction, write-downs after secret access — are invisible to the pipeline and therefore never generate a recommendation.

This issue proposes extending the data model, tagging, scoring and testing to distinguish **message rails** from **conversation rails**, enforced through NeMo Guardrails (Colang flows reading `$history`). Checks in other policy engines — notably the [Praxis Policy Engine (PPE)](https://github.com/praxis-proxy/policy) — are referenced as *design precedents* for what conversation-level validation looks like. This issue assumes no integration with them — but the design keeps the door open: the `enforcement:` field is extensible, so other backends can be added later without reworking the model.

## Goals

1. Rail cards carry a `scope` (`message` | `conversation`).
2. The transcript the recommender already loads (`AttackRecord.messages`, `attack_turn_index`) is actually consumed by tagging, scoring and testing.
3. A new class of **trajectory signals** computed over the whole transcript (deterministic heuristics + one cached LLM call, preserving determinism and the `--no-llm` offline story).
4. Scope-aware scoring: a card only matches signals of its own scope.
5. Recommendation output gains a **placement dimension**: message rails → any stateless check endpoint (e.g. `/v1/checks`); conversation rails → a history-aware endpoint (NeMo Colang `$history`). The dimension is extensible to other backends later.
6. `test_rails.py` can replay transcripts turn-by-turn and assert the block lands on the right turn.

## Non-goals

- Changing existing message-rail behavior. **Note: the `examples/run1` golden output will change** — its attacks include multi-turn transcripts, so trajectory signals will fire and alter selection. Per repo convention, run1 must be regenerated in the same change; this issue does not promise output stability.
- Generating non-NeMo outputs. This issue builds only `nemo-flow` enforcement; PPE and other backends are future extensions (see the connection sections below).

## Background: what conversation-level checks look like elsewhere

The recommender's only enforcement runtime is a NeMo Guardrails server. For conversation rails, the enforcement mechanism within NeMo is Colang flows reading `$history` on a stateful endpoint.

To ground the *catalog* of possible conversation checks, this issue borrows design ideas from other policy engines — primarily the [Praxis Policy Engine (PPE)](https://github.com/praxis-proxy/policy), which already implements session-state and history-scanning checks over agent traffic. **These are precedents for the shape of the checks**: ASAGO does not depend on PPE today, and nothing in this issue requires it to. The examples below are cited because they are well-specified, working implementations of exactly the class of control the catalogue lacks — and, if an integration ever makes sense later, a concrete starting point for it.

(For context only: PPE exists because proxy-side enforcement — an in-path component that sees every request with full history and knows which agent it is fronting — is an alternative placement for guardrails in general. That placement is what makes its tool-call-state checks possible, since a `/v1/checks` service never sees tool calls. If ASAGO ever adopts such a placement, the deferred tool-call-state rails below are where it would start.)

## Placement reasoning

A guardrail's enforcement point follows from the context its correctness requires — a check can only act on what reaches it.

- The binary `scope: message | conversation` is a first cut of that context axis: message rails are *content-aware* checks; conversation rails are *session-state* checks. The field is designed to extend — a future *user-intent correlation* class (e.g. intent-based access control on tool calls) would arrive as a third value, and belongs with the deferred tool-call-state rails.
- Conversation checks are usually placed where session state is held in or beside the workload. The `nemo-flow` backend works at a check-service point anyway because LLM protocols forward the full conversation on every request — the caller supplies the history, so the check service receives its context from the caller. Stated plainly so the limit is visible: this works only while callers faithfully forward history, and only for checks over the message channel; it does not generalize to tool-call or egress traffic, which need an enforcement point that sees them directly.
- For stateful backends generally, the durability of session state and the distinction between "last intent" and full accumulated history are the right lens for the fail-open/fail-closed question below.

## Why conversation rails need different machinery

A clean final message proves nothing about the conversation that produced it. The controls below are all decided from history or session state, which is exactly what a per-message `/v1/checks` call cannot see.

## Candidate multi-turn validations/checks

### Design precedents implemented in the Praxis Policy Engine

These exist today in `praxis-proxy/policy` as working implementations of conversation-level checks. They are referenced as precedents for the catalogue — which checks are worth having and how they behave. This issue wires up none of them; its only backend is NeMo (see Proposed changes):

1. **Session Taint / write-down prevention** ([docs/content/apl/tainting.md](https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/tainting.md)) — `taint(secret, session)` attaches a monotonic label when a session reads sensitive data; any later external-send route is denied via `security.labels contains "secret"` even with a clean payload. Labels live in PPE-owned state (in-memory or the bundled Valkey store, surviving restarts), scoped per subject so shared sessions don't leak labels. Would be: *deny external sends after secret data was accessed* (deferred — tool-call state).

2. **Transcript scanning** ([reference/plugins/transcript-scanner](https://github.com/praxis-proxy/policy/tree/main/reference/plugins/transcript-scanner)) — a CMF plugin that regex-scans the entire conversation history (text, thinking, tool-call arguments, tool results, resources, blobs) and denies naming the pattern and turn, never the matched text. Requires the `read_agent` capability, or history is filtered to empty. In-scope card: *block if a forbidden pattern appears anywhere in history* — catches payloads smuggled in early and referenced later.

3. **Per-session token/call quotas** (`experimental-quota` feature) — cumulative budgets across a session, not per request. Would be: *rate-limit / context-exhaustion ("many-shot") resistance* (deferred — tool-call state).

4. **Out-of-band approval / elicitation** (CIBA-backed) — an action is suspended until a human approves it, with correlation state held across turns. Would be: *human sign-off before high-risk actions* (deferred — tool-call state).

5. **Redaction and result filtering** — field-level redaction in transit (`ssn: "str | redact(!perm.view_ssn)"`) prevents sensitive data from ever entering history, which is the *prevention* counterpart to taint's *detection* (deferred — output/tool-result).

### Available in NeMo Guardrails

- **Colang dialog rails over `$history`** — topical/dialog flows that carry per-conversation state; caller passes full history per request. Suitable when enforcement stays on a NeMo server rather than moving to a proxy.

## Proposed changes

### 1. Catalog (`guardrail-catalog/`)

- Add `scope: message | conversation` to rail cards (default `message`).
- New conversation rail cards for the **in-scope** checks (transcript/history scanning and drift/incremental-jailbreak detection), with `detects` entries using trajectory signal names (below) and an `enforcement: nemo-flow` backend (a Colang flow using `$history`). The `enforcement:` field leaves room for other backends later, but NeMo is the only one this issue builds. The tool-call-state checks above (taint, quotas, elicitation, redaction) are **not** cards in this issue; they are precedents only, deferred to the planned output-guardrails work.

### 2. Attacks (`attacks.py`)

- No data-model change: `AttackRecord.messages` and `attack_turn_index` already hold the transcript. The change is downstream — tagger, scorer and tester start consuming them. (One upstream note: attacks are captured *up to and including* the attack turn; gradual attacks whose payload lands in later turns would need the artifact generator to emit post-attack turns. That is an upstream consideration, not part of this issue.)

### 3. Tagging (`tag.py`)

- Trajectory signals over the transcript, deterministic first:
  - `jailbreak:incremental` — refusal followed by rephrase of the same intent
  - `drift:<topic>` — distance between opening topic and current turn
  - `attempt_count:gt_N` — repeated probes of a refused request
  - `pii:distributed` — one entity assembled across multiple turns
- One LLM call judging the trajectory, cached by attack id (same cache design).
- **Reuse the upstream taxonomy, don't parallel it:** trajectory signal names should be derived from the scenario metadata the recommender already loads (`threat_id`, `mechanism`, OWASP/ATLAS/LAAF ids), so multi-turn signals stay traceable to the policy risks the way message signals are.

### 4. Scoring/selection (`recommend.py`)

- Scope-aware intersection: message cards match message signals only; conversation cards match trajectory signals only.
- Selection rule: at most 1 conversation rail per option (stateful, expensive).
- Output `Option` gains `placement` per rail.

### 5. Config generation

- `nemo-flow` → Colang flow using `$history`, merged into the option's NeMo configuration like message-rail cards today.

### 6. Testing (`test_rails.py`)

Testing splits by backend, because `/v1/checks` cannot exercise stateful conversation rails: it is stateless and evaluates **every message in a request independently**, so replaying history through it would either false-block on earlier turns or test something other than the rail's stateful behavior.

- **`nemo-flow` rails:** need a stateful evaluation path (e.g. the chat endpoint with caller-supplied history); `/v1/checks` cannot serve this role. Identifying or adding the right harness is part of the work.
- Message-rail testing via `/v1/checks` is unchanged.
- (If a second backend is added later — e.g. a policy engine — its testing story would be replaying the transcript through that engine directly; out of scope here.)

## Relationship to the rest of the ASAGO pipeline

Checked against `docs/asago-pipeline.md` and `docs/design.md` to avoid duplication and to state boundary changes explicitly:

- **Upstream stages need no change.** The artifact generator already emits multi-turn garak transcripts, and `attacks.py` already loads them into `AttackRecord.messages`. This issue only makes downstream stages consume what is already loaded. (Post-attack-turn gradual attacks are the one possible future upstream ask.)
- **Baseline evaluation (step 3b, [asago-examples PR #35](https://github.com/asago-ai/asago-examples/pull/35)) is not duplicated.** It replays transcripts against the *unprotected* model with an LLM judge to record `baseline_outcome`. The transcript replay proposed for `test_rails.py` targets the *rail configurations* instead; the two share the shape of the harness but answer different questions (is the app vulnerable vs do the recommended rails block it, and on which turn).
- **Efficacy/gap reporting extends the existing channel.** Trajectory signals that no catalogue rail detects feed the existing gap list ([design.md §5.4](https://github.com/asago-ai/asago-guardrails-recommender/blob/main/docs/design.md)), so multi-turn gaps are reported through the same channel as message gaps.
- **Boundary is sequencing:** [design.md §8](https://github.com/asago-ai/asago-guardrails-recommender/blob/main/docs/design.md) states "Input guardrails only. Output, tool-call and tool-return guardrails are out of scope" — a point-in-time statement; output guardrails are already planned. The strongest PPE examples — Session Taint on tool reads, quotas, out-of-band approval of actions, tool-result redaction — are tool-call and output guardrails, and are the natural content of that planned expansion. This issue splits accordingly:
  - In scope here: history/message-level conversation rails (transcript scanning, Colang `$history` flows, drift/incremental-jailbreak detection).
  - Deferred to the output-guardrails work: tool-call-state rails (taint, quotas, elicitation, redaction). They also need an enforcement point that sees tool calls — which a `/v1/checks` service never does.

## Connection to the Praxis Policy Engine (concrete, for later)

This issue builds no PPE output. But the connection is specific enough to state now, because the recommender already has the pattern of generating policy configs for other engines: [Support generating OpenShell policies](https://github.com/asago-ai/asago-guardrails-recommender/issues/12) and [Support generating a Decision Model policy](https://github.com/asago-ai/asago-guardrails-recommender/issues/5). A PPE output would follow the same shape:

- **What ASAGO would generate:** a `transcript-scanner` plugin `config:` block per conversation rail card — the rail card's patterns and role filters, in the plugin's documented config schema. That schema is the entire contract between the projects.
- **What the test harness would need:** a way to run PPE headless over a transcript — register the plugin, feed the conversation, assert the deny — analogous to how `test_rails.py` drives a NeMo server today. PPE's `praxis-policy` crate with `builtins` and its reference plugins suggest this is possible, but it is not a documented embedding path.
- **The concrete open item for PPE maintainers:** the transcript-scanner lives in `reference/plugins/` — worked examples that are linted and tested but *not published and not bundled*. Generating configs for it in a recommender presumes it becomes a supported plugin with a stable config schema. That is the question to bring to the PPE maintainers.
- **Versioning:** PPE's public API moves between minor versions; a generated-config output would need to pin and advertise a tested PPE version.

## Connection to enforcement points (concrete, for later)

[Praxis AI](https://github.com/praxis-proxy/ai), an AI gateway built on Praxis, already ships an `ai_guardrails` filter that calls a NeMo Guardrails server via `/v1/checks` in-path, with per-request `config_ids` selecting the configuration — the same config-per-option model ASAGO's deploy step produces. It evaluates request, response, and tool-result phases, supports redaction, and fails closed. This is an existing consumer for ASAGO's generated NeMo configs today, and an in-path enforcement point that sees full request bodies (conversation history included) for conversation rails later.

[Cortex](https://github.com/rossoctl/cortex) is a local proxy that hosts an agent behind a processing pipeline, terminating its outbound TLS, processing every LLM and tool request, and knowing which agent it fronts. It is therefore an enforcement point that already holds what conversation rails need: full request history plus agent identity. If ASAGO's PPE output lands, a cortex-hosted deployment is where those configs would execute — per-agent rail sets map onto cortex's per-agent identification, and the configs load as gateway policy. Nothing in this issue depends on that.

## Open questions

- Sequencing with the planned output-guardrails expansion: do the tool-call-state rails (taint/quota/elicitation/redaction) ride with that work, and should this issue land first so conversation-scope machinery (signals, scoring, placement) is already in place for it?
- Should conversation rails be tiered like message rails (regex/heuristic vs model-based), given PPE checks are deterministic but Colang `$history` flows may need an LLM?
- Fail-open vs fail-closed when a stateful backend (PPE session store, NeMo server) is unavailable mid-session.
