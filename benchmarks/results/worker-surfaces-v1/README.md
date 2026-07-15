# Task, scheduler, CLI, and worker surfaces v1

Issue: [#95](https://github.com/shaggitza/test_ast_fastapi/issues/95)

The package-owned `workers-v1` preset adds exact custom-surface contracts for
Celery, RQ, Arq, APScheduler, Click, Typer, argparse, Dramatiq, and the Celery
`worker_ready` lifecycle signal.

## 50-project prioritization survey

`benchmarks/real_world/surveys/worker-adapters-v1.json` freezes 50 unique public
repositories at exact blob commits using exact GitHub code-search evidence. It
is a prioritization survey, not adjudicated recall truth. The candidate counts
are:

| Candidate family | Projects |
|---|---:|
| Celery | 18 |
| APScheduler | 8 |
| RQ | 7 |
| Arq | 7 |
| Typer | 7 |
| Click | 3 |

This evidence prioritized Celery first, then APScheduler, explicit RQ/Arq worker
registration, and Typer/Click CLI roots. Argparse, Dramatiq, and lifecycle
contracts are included as bounded exact adapters but are not represented as
survey-frequency claims.

## Explicit execution semantics

Every surface preserves both callback shape and executor boundary:

- Celery, RQ, and Dramatiq: synchronous callback / process worker;
- Arq: asynchronous callback / event loop;
- APScheduler: sync or scheduler-supported callback / scheduler boundary;
- Click, Typer, and argparse: synchronous callback / CLI dispatch;
- Celery `worker_ready`: synchronous callback / process-worker lifecycle.

These declarations create roots only. They do not claim persistence, observation,
resource coupling, or changed-code-to-call causality.

## Controlled matrix

Fixtures cover decorator and imperative registration, exact callback identity,
explicit public IDs, documented Click/Typer kebab-case defaults, callback-mode
rejection, executor provenance, same-method-name negatives, changed-handler
impact, all output formats, and load-once package preset configuration. Celery
and APScheduler require explicit `name`/`id`; RQ requires an explicit literal
queue. Missing values are omitted rather than deriving module paths, scheduler
IDs, or the conventional RQ `default` queue. Argparse retains
a conditional handler-keyed surface because public subcommand identity is held
in parser state unavailable to schema v1.

## Pinned real PRs

`benchmarks/real_world/expansion/workers-v1.json` records four merged cases:

- `yura2787/auto_monitor#4`: module-level exact Celery tasks with public names;
- `kenil-sarang-itp/codebase-brain#8`: RQ enqueue-by-string and runtime queue
  factories, intentionally unavailable rather than convention-guessed;
- `fitz-s/zeus#324`: APScheduler cron `add_job` with explicit ID but a receiver
  whose construction must remain source-proven;
- `JeffCarpenter/github-to-sqlite#16`: module-level Typer commands with explicit
  and handler-derived names.

An execution-free extractor run on the pinned merge snapshots recovered all
three explicitly named Celery tasks in `auto_monitor#4` and 16 Typer CLI roots
in `github-to-sqlite#16`. The Celery case crosses an exact project-local module
global (`from tasks.celery_app import celery_app`); only that finite alias is
followed.

The negative RQ shape demonstrates the boundary: enqueuing a string path does
not prove that every named worker function is registered in the analyzed
snapshot.

## Primary API evidence

- <https://docs.celeryq.dev/en/stable/userguide/tasks.html>
- <https://python-rq.org/docs/>
- <https://apscheduler.readthedocs.io/en/3.x/userguide.html>
- <https://click.palletsprojects.com/en/stable/api/>
- <https://typer.tiangolo.com/>
