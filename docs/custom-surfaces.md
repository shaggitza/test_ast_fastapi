# Declarative custom surfaces

Custom surface contracts let the execution-free analyzer treat message listeners,
tools, tasks, schedulers, CLIs, workers, and other reactors as application
entrypoints. They are strict YAML, JSON, or TOML data. They cannot import project
code or run Python plugins.

Configure a document relative to `.endpoint-detector.yaml`:

```yaml
analysis:
  surface_contracts: surfaces.yaml
```

Analysis must use `--secure-ast`. Validate configuration independently:

```bash
fastapi-endpoint-detector validate-surface-contracts \
  --contracts surfaces.yaml --format json
```

See [`examples/surface_contracts.yaml`](../examples/surface_contracts.yaml).

For the bundled RabbitMQ/Kafka adapter, select the package-owned preset instead
of a custom document:

```yaml
analysis:
  surface_preset: event-listeners-v1
```

`surface_preset` and `surface_contracts` are mutually exclusive so one analysis
has one unambiguous config/raw/preset provenance chain.

## Event-listener preset

`event-listeners-v1` contains exact contracts for:

- `faststream.rabbit.RabbitBroker.subscriber`, with one literal queue;
- `faststream.kafka.KafkaBroker.subscriber`, with one or more literal topics;
- `aio_pika.queue.Queue.consume`, with an exact async callback.

FastStream registrations can be established when the receiver, async decorated
handler, and every queue/topic string are source-proven. Kafka multi-topic
positional arguments are normalized into sorted, deduplicated surfaces, capped
at 32 resources per registration. Literal lists, tuples, and sets are also
finite. If any member is dynamic, the entire registration fails closed; known
members are never partially emitted and unknown topics never cause topic-wide
fanout.

Aio-pika queue identity normally originates in an awaited `declare_queue`
factory and is not available to schema v1. The preset therefore emits only a
conditional `rabbitmq handler:<callback>` surface when an exact `Queue.consume`
receiver is otherwise source-proven. It never invents or fans out queue names.
This limitation is preserved in discovery evidence.

These contracts follow the documented FastStream Rabbit
[`subscriber`](https://faststream.ag2.ai/latest/rabbit/) and Kafka
[multi-topic subscriber](https://faststream.ag2.ai/latest/kafka/Subscriber/)
APIs and aio-pika's callback-based
[`Queue.consume`](https://docs.aio-pika.com/apidoc.html#aio_pika.queue.Queue.consume)
API.

## MCP preset

Select `mcp-v1` to discover FastMCP tools, resources, and prompts:

```yaml
analysis:
  surface_preset: mcp-v1
```

The preset supports both `fastmcp.FastMCP` and the official Python SDK's
`mcp.server.fastmcp.FastMCP` exact identities. It recognizes called and bare
`tool`, `resource`, and `prompt` decorators, plus imperative `add_tool` and
`add_prompt` registration of one project-local function.

Tools and prompts use an explicit literal `name=` when present and otherwise use
the physical handler name. An explicit dynamic name fails closed instead of
falling back. Resources preserve the exact literal URI or URI template from the
positional `uri` argument or `uri=` keyword. Surface kinds remain distinct:
`mcp.tool`, `mcp.resource`, and `mcp.prompt`.

Sync and async handlers are both valid because FastMCP executes sync components
in its thread pool and async components on the event loop. Context/dependency
parameters do not change callback identity. Duplicate exposed IDs retain every
physical handler as conditional evidence rather than silently applying
FastMCP's runtime replacement policy. Dynamic plugin registries, bound-method
objects, component instances passed to `add_resource`, and runtime enable/disable
mutation remain unresolved.

The preset follows FastMCP's documented
[`tool`](https://gofastmcp.com/servers/tools),
[`resource`](https://gofastmcp.com/servers/resources), and
[`prompt`](https://gofastmcp.com/servers/prompts) APIs.

## Schema v1

Each document has `schema_version: 1`, preset identity/provenance, and one or
more contracts. Unknown fields, duplicate keys, duplicate contract IDs,
duplicate matcher/handler selectors, non-integer schema versions, and files over
1 MiB are rejected.

A contract declares:

- `registration.symbol`: a fully qualified callable identity pattern;
- `registration.invocation`: `function`, `instance_method`, or `class_method`;
- `registration.receiver_type`: mandatory exact type for method registrations;
- `handler`: `decorated_function`, positional `argument`, or named `keyword`;
- `surface.kind`: a stable lower-case surface class;
- `surface.id_template`: exactly one `{resource}` placeholder;
- `surface.resource`: a literal string argument/keyword, all positional arguments from a bounded index, handler name, or fixed literal;
- `callback_mode`: `either`, `sync`, `async`, `generator`, or `async_generator`;
- optional external `conditions`, which make discovery conditional.

For example:

```yaml
- id: rabbit-orders
  registration:
    symbol: messaging.RabbitBroker.subscriber
    invocation: instance_method
    receiver_type: messaging.RabbitBroker
  handler:
    kind: decorated_function
  surface:
    kind: rabbitmq
    id_template: "queue:{resource}"
    resource: {kind: argument, index: 0}
  callback_mode: async
```

This recognizes only a source-proven `messaging.RabbitBroker` receiver. Another
type with a method named `subscriber` never matches.

## Exact and wildcard matching

Exact fully qualified symbols are the default and can establish a surface when
the registration, literal resource, and unique project-local handler are all
source-proven.

A `*` replaces one identity segment only. The callable name cannot be a wildcard,
the segment count must remain equal, and at least two owner segments must remain
exact. Method contracts still require one exact receiver type. Every wildcard
result is conditional and therefore centrally capped LOW; wildcard evidence can
never promote confidence.

There is no suffix matching, bare method matching, spelling fallback, arbitrary
glob syntax, receiver candidate fanout, or executable selector language.

## Provenance and limits

Every custom endpoint preserves:

- surface kind, ID, and literal resource;
- contract ID and exact/wildcard match strength;
- registration symbol, file, line, and column;
- callback mode and declared conditions;
- raw, config, preset, and per-contract SHA-256 hashes;
- normalized registration-source and handler-source hashes.

JSON and YAML expose this as `endpoint.surface`; text, Markdown, and HTML include
the contract, strength, registration location, and config hash.

Only explicit imports, module attributes, finite constructor receivers, and
unique project-local function handlers are supported. Rebinding, ambiguous
handlers, dynamic factories, members stored in containers, non-literal resource
IDs, reflection, and unsupported control flow fail closed. Conditional matches
remain visible with source-backed limitations. These contracts create analysis
roots; they do not declare state effects or behavioral observation. Use effect
contracts separately for call semantics.
