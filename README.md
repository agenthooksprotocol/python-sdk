# Agent Hooks Protocol SDK for Python

Typed Python models and JSON codecs for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The SDK follows the current AHP `draft` schema snapshot and requires Python 3.11 or newer.

## Installation

The package is not yet published to PyPI. Until the first release, pin it directly from GitHub:

```sh
python -m pip install \
  "agent-hooks-protocol @ git+https://github.com/agenthooksprotocol/python-sdk.git@main"
```

For reproducible builds, replace `main` with a commit SHA.

## Quick start

Every public AHP schema has a typed model, a `parse_*` function, and an `encode_*` function.

```python
from agent_hooks_protocol.generated import (
    encode_capabilities,
    parse_capabilities,
)

result = parse_capabilities(
    '{"effects":["deny"],"com.example.preview":true}'
)

if not result["ok"]:
    raise ValueError(result["diagnostics"])

capabilities = result["value"]
print(capabilities["effects"])

encoded = encode_capabilities(capabilities)
```

Parsers accept either JSON text or an already-decoded JSON value. Successful results contain:

- `value`: the typed model
- `raw`: the preserved JSON value
- `diagnostics`: compatibility warnings, such as an unknown enum value

Failed results contain structural diagnostics with a JSON Pointer `path`, machine-readable `code`, `severity`, and message.

## API

The generated module exports:

- `SCHEMA_REVISION` and `PROTOCOL_VERSION`
- typed models for registrations, JSON-RPC messages, hook events, requests, responses, capabilities, and effects
- `parse_<root>(input)` for structural parsing
- `encode_<root>(value)` for JSON encoding
- `ParseResult`, `ParseDiagnostic`, and JSON value aliases

Unknown object fields and unknown discriminator or enum values are retained for forward compatibility. JSON numbers are decoded without losing decimal precision. Parsers do not coerce values, insert defaults, or discard extension data.

## Development

```sh
git clone https://github.com/agenthooksprotocol/python-sdk.git
cd python-sdk
python -m compileall -q src tests
PYTHONPATH=src python -m unittest discover -s tests
```

Generated code lives in `src/agent_hooks_protocol/generated.py`. Its provenance is recorded in `ahp-codegen.lock.json`; schema changes are made in the [protocol repository](https://github.com/agenthooksprotocol/agent-hooks-protocol), not by editing the generated file.

## License

Apache-2.0
