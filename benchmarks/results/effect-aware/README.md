# Effect-aware validation

## Open WebUI PR #26906

Source: https://github.com/open-webui/open-webui/pull/26906

The PR adds a shallow defensive copy before pipe base-model substitution. The
new analyzer keeps all 13 call-reachable HTTP candidates and separates execution
reachability from caller-visible observation:

- **HIGH (2 route aliases):** `/api/chat/completions` and
  `/api/v1/chat/completions`. The original payload flows into a derived response
  context returned to response processing and later continuation behavior.
- **MEDIUM (2 route aliases):** `/api/message` and `/api/v1/messages`. They
  consume the changed chat-completion result and return a converted response,
  but the concrete response branch is runtime-dependent.
- **LOW (9):** chat compaction and eight task-completion routes. They execute the
  changed callable, so they are not reachability false positives. Their locally
  constructed caller payload has no established post-call observation. Dynamic
  pipe code may still observe object identity, and the copy remains shallow.

The two high- and two medium-confidence aliases remain in the legacy selected
output. The nine low-confidence routes remain available under
`candidate_endpoints`; they are not
silently discarded from the canonical evidence.

`open-webui-pr-26906.json` is a compact extraction of the real analyzer report,
including every candidate's structured data-flow evidence. The full report was
generated from merge commit `f8c0d2fdd690ecbe0444617c91dba3be45d5681e`
with secure AST discovery and cache disabled.
