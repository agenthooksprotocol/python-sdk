# Agent Hooks Protocol Python SDK

Official, non-normative Python models and structural codecs for the [Agent Hooks Protocol](https://github.com/agenthooksprotocol/agent-hooks-protocol).

> [!WARNING]
> A successful structural parse is not canonical schema validation and must not be used alone for authorization or response classification. Validate security-sensitive messages against the canonical Draft 2020-12 schemas.

## Development

Python 3.11 or newer is required.

```sh
python -m compileall -q src tests
PYTHONPATH=src python -m unittest discover -s tests
```

`src/agent_hooks_protocol/generated.py` and `ahp-codegen.lock.json` are maintained by schema-sync automation. Do not edit them manually.
