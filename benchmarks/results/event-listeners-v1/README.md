# Event-listener surface adapter v1

Issue: [#93](https://github.com/shaggitza/test_ast_fastapi/issues/93)

This adapter is a package-owned declarative surface preset layered on the strict
schema from #92. It does not import broker libraries or application code.

## Controlled matrix

Unit and integration fixtures cover:

- exact FastStream `RabbitBroker.subscriber` decorators;
- exact FastStream `KafkaBroker.subscriber` decorators with multiple positional
  topics;
- exact imperative `aio_pika.queue.Queue.consume(callback)` registration;
- async callback enforcement;
- literal list/tuple/set normalization and deterministic deduplication;
- all-or-nothing rejection when any resource is dynamic;
- package preset loading, load-once configuration, and changed-handler impact.

Finite resource sets are sorted and capped at 32 identities. Unknown resources
never emit partial registrations and never fan out across known topics/queues.

## Real-source audit

Two merged RabbitMQ PRs were inspected as adversarial shapes:

- [`MauriDev94/event-driven-orders#8`](https://github.com/MauriDev94/event-driven-orders/pull/8)
  obtains an aio-pika queue in an async FastAPI lifespan using
  `await broker.channel.get_queue(ORDER_CREATED_QUEUE)`, builds the handler from
  a runtime factory, and then awaits `queue.consume(handler)`. Queue and callback
  identities are not finite under schema v1, so this pattern remains unresolved
  rather than inventing an entrypoint or queue-wide fanout. Lifecycle execution
  belongs to #104.
- [`Pavel14701/smart_house_bot#4`](https://github.com/Pavel14701/smart_house_bot/pull/4)
  registers `router.subscriber("stt_command")(self.process_audio)` inside a class
  constructor. The mutable injected router and bound callback are intentionally
  unresolved; method-name spelling does not activate the preset.

These negatives are deliberate rollback cases. Module-level exact FastStream
decorators are established; dynamic lifecycle factories, injected plugin
registries, and constructor-time rebinding stay conditional or unavailable
until separately modeled with source-proven semantics.

## External API evidence

- FastStream Kafka documents multiple positional topics for one subscriber:
  <https://faststream.ag2.ai/latest/kafka/Subscriber/>
- aio-pika documents coroutine callbacks for `Queue.consume`:
  <https://docs.aio-pika.com/apidoc.html#aio_pika.queue.Queue.consume>
