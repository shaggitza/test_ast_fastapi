# FastMCP/MCP surface adapter v1

Issue: [#94](https://github.com/shaggitza/test_ast_fastapi/issues/94)

The `mcp-v1` package preset layers exact FastMCP semantics on the strict custom
surface schema from #92. It supports both `fastmcp.FastMCP` and the official
Python SDK identity `mcp.server.fastmcp.FastMCP` without importing either
package.

## Controlled matrix

Fixtures cover:

- bare and called tool/prompt decorators;
- positional and keyword resource URIs and URI templates;
- explicit literal tool/prompt names with handler-name fallback only when the
  keyword is absent;
- imperative `add_tool` and `add_prompt` registration of exact project-local
  functions;
- sync, async, and injected `Context` handler signatures;
- distinct `mcp.tool`, `mcp.resource`, and `mcp.prompt` surface kinds;
- duplicate exposed IDs retaining both physical handlers as conditional;
- dynamic names and dynamic plugin receivers failing closed;
- changed-handler impact through the package preset.

The adapter does not model FastMCP's runtime duplicate replacement policy as
static truth. Duplicate identities remain visible so no physical handler
evidence is deleted.

## Expanded real-repository candidates

`benchmarks/real_world/expansion/mcp-v1.json` pins two merged repositories for
the 50-project expansion in #103:

- `orenlab/ckdn#8` (`6b22eddeac5a...`) adds six FastMCP tools through register
  functions whose server receiver is dynamically imported and injected;
- `dmbch/lore#51` (`cc5561c3c994...`) moves assembly to a FastMCP factory and
  lifespan architecture.

Both are intentional adversarial negatives for v1: registration occurs in
deferred factory scopes with receiver identity unavailable to the module-level
secure extractor. They remain conditional or unavailable rather than being
recovered by `tool` spelling. The pinned entries make those limits explicit for
the later expanded-corpus runner instead of representing them as successful
recall.

## API evidence

- <https://gofastmcp.com/servers/tools>
- <https://gofastmcp.com/servers/resources>
- <https://gofastmcp.com/servers/prompts>
