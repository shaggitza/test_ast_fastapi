# Output configuration

Pass `Config.output` to the formatter factory to apply output presentation settings:

```python
formatter = get_formatter("text", output_config=config.output)
rendered = formatter.format(report)
```

Calling `get_formatter(name)` without an output config and constructing a formatter directly keep
their legacy display behavior. Configured human-readable formatters use `OutputConfig` values.
Presentation settings affect rendered text only: they do not modify the analysis report, candidate
set, evidence, inventory limitations, confidence levels, threshold selection, or accounting.

| Option | Text | Markdown | HTML | JSON / YAML |
| --- | --- | --- | --- | --- |
| `show_confidence` | Supported | Supported | Supported | Non-default value rejected |
| `show_dependency_chain` | Supported | Supported | Supported | Non-default value rejected |
| `colorize` | Supported; `false` emits no ANSI escapes | `false` rejected | `false` rejected | Non-default value rejected |
| `verbose` | Supported | Supported | Supported | Non-default value rejected |

When confidence display is disabled, human output omits confidence names, icons, and confidence
styles. This does not change confidence evidence or selection. Verbose output adds the changed-file
paths already recorded for each affected endpoint and additional candidate. It does not infer new
diagnostics.

When dependency-chain display is disabled, text and Markdown omit both the chain and traceback
views. HTML omits the chain, linear traceback disclosure, and interactive condensed call-path graph;
that graph is a path visualization and is controlled by the same setting. JSON and YAML always keep
their complete schema, including chain and call-stack fields. Passing a non-default presentation
setting to either structured formatter raises a `ValueError` naming the option and format rather
than silently dropping data. `colorize=false` is only meaningful for terminal text output and is
also rejected by Markdown and HTML.

The factory accepts `OutputConfig` or a mapping with the four known option names. Unknown mapping
keys and unknown format names raise `ValueError` with the invalid name. Every supplied option
value must be a boolean; non-boolean values raise `ValueError` naming the option and format instead
of relying on Python truthiness.
