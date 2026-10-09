The `message-bus-v1` preset declares two exact typed SQS publishing symbols:
`mypy_boto3_sqs.client.SQSClient.send_message` and `send_message_batch`.
The queue resource selector is the `QueueUrl` keyword. The value selector is
`MessageBody` for a single message and `Entries` for a batch. Batch entries are
treated as one argument; the preset does not infer individual message contents,
delivery, acknowledgement, durability, or consumer reachability.

Version 1.0.0, revision 1, was checked against the supplied
`mypy_boto3_sqs-1.35.91-py3-none-any.whl` artifact, SHA-256
`346a87bc0a447bb4c005b04d3efa0008bfa0ddd498cadd97e0e53a58752f84e9`.
Its `client.py` hash is
`a79cac0f3445a6008f02b2def173dda53e868d9630d12ae4ae7806e41aefba3b`;
its `type_defs.py` hash is
`76f2dfdc73b3fc623c8feb455d1fa079f22b4f4fd80b3f1f5df64fb7c8b5f013`.
Both methods use keyword-only request fields through typed `**kwargs`.
`QueueUrl` and `MessageBody`, or `QueueUrl` and `Entries`, are required fields
in the corresponding request TypedDict. No upstream client code was executed.

The package applicability metadata names only that inspected release. The
effect auditor currently does not enforce installed package versions; callers
must establish their package version separately. Other releases, untyped
`boto3.client` factories, runtime clients, and real-world evaluation are not
validated by this declaration. The historical six-preset matrix remains frozen;
this new preset does not alter its archived results.

Changelog: 1.0.0 adds the two exact SQS declarations and their queue/value
selectors. No generic `send`, `publish`, or same-name matching is introduced.
