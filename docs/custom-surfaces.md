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

## Framework callback preset

Select `framework-v1` for exact FastAPI/Starlette startup, shutdown, and HTTP
middleware surfaces:

```yaml
analysis:
  surface_preset: framework-v1
```

The preset is execution-free and uses exact receiver identities. Schema-v3
constructor contracts split exact `FastAPI(lifespan=...)` async generators into
pre-yield startup and post-yield shutdown ranges. It does not model class-based
middleware. BackgroundTasks
and dependency providers are handled by typed execution summaries rather than
surface registration contracts. See [framework semantics](framework-semantics.md).

## Worker and CLI preset

Select `workers-v1` for exact Celery, RQ, Arq, APScheduler, Click, Typer,
argparse, Dramatiq, and Celery worker-lifecycle surfaces:

```yaml
analysis:
  surface_preset: workers-v1
```

Each contract declares both `callback_mode` and `execution_mode`. Execution
modes distinguish process workers, event-loop workers, schedulers, CLI dispatch,
thread pools, framework callbacks, and direct invocation. They describe the
registration boundary only and never imply effect observation or persistence.

Public IDs come only from literal registration arguments/keywords or the exact
physical handler name where the framework documents that default. Click and
Typer handler defaults use their documented underscore-to-hyphen normalization.
Celery task names and APScheduler job IDs must be explicit. RQ's default queue is
deliberately not guessed: bare `@job` is unresolved unless a user supplies a
custom contract with an explicit resource. Argparse callback handlers
are conditional because `set_defaults(func=...)` does not source-prove the
public subcommand name.

The preset does not infer string-path RQ enqueue targets, Celery autodiscovery,
Arq `WorkerSettings` class registries, entry-point plugins, cron files, or CLI
function naming conventions. Those shapes remain unavailable unless their
registration is explicitly represented in source or configured with a custom
contract.

## Schema v1, v2, v3, and v4

Each document has `schema_version: 1`, `2`, `3`, or `4`, preset
identity/provenance, and one or more contracts. Version 1 preserves direct
execution as its only boundary; version 2 adds explicit `execution_mode`;
version 3 adds constructor registrations, optional keyword handlers, and
yield-relative callback ranges. Version 4 adds exact positional local-class
method handlers constrained by a contract-owned base and method name. Earlier
schemas reject these additions. Unknown fields, duplicate keys, duplicate contract IDs,
duplicate matcher/handler selectors, non-integer schema versions, and files over
1 MiB are rejected.

A contract declares:

- `registration.symbol`: a fully qualified callable identity pattern;
- `registration.invocation`: `function`, `instance_method`, `class_method`, or v3 `constructor`;
- `registration.receiver_type`: mandatory exact type for method registrations;
- `handler`: `decorated_function`, positional `argument`, named `keyword`, or v4
  `argument_class_method` with an argument index, direct method name, and exact base;
- `surface.kind`: a stable lower-case surface class;
- `surface.id_template`: exactly one `{resource}` placeholder;
- `surface.resource`: a literal string argument/keyword, all positional arguments from a bounded index, handler name, or fixed literal;
- `callback_mode`: `either`, `sync`, `async`, `generator`, or `async_generator`;
- `callback_range` (v3): `full`, `before_yield`, or `after_yield`;
- `handler_optional` (v3): skip a constructor contract when its named callback keyword is absent;
- `execution_mode` (v2): `direct`, `event_loop`, `threadpool`, `process_worker`, `scheduler`, `cli_dispatch`, or `framework`;
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

Only explicit imports, module attributes, finite constructor receivers, unique
project-local function handlers, and v4 exact direct methods on unique local
classes are supported. Class methods require the sole exact declared base from
the contract. Rebinding, ambiguous handlers, dynamic factories, inherited-only
methods, decorated classes, members stored in containers, non-literal resource
IDs, reflection, and unsupported control flow fail closed. Conditional matches
remain visible with source-backed limitations. These contracts create analysis
roots; they do not declare state effects or behavioral observation. Use effect
contracts separately for call semantics.
