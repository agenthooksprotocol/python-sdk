# Migrating

## 0.5 → next (unreleased)

### Observation declarations

`capability.Observe` was removed. Every event now has its own declaration
type. To declare observation, pass `observe=True` to that event's
`<Event>Capabilities`. For observation-only events (`session.end`,
`file.changed`, `turn.end`, ...), `observe=True` is the only option. An empty
declaration such as `SessionEndCapabilities()` raises `ValueError`.

Before:

```python
from agenthooksprotocol import capability

capabilities = capability.HostCapabilities(
    tool_before=capability.Observe(),
    session_end=capability.Observe(),
)
```

After:

```python
from agenthooksprotocol import capability

capabilities = capability.HostCapabilities(
    tool_before=capability.ToolBeforeCapabilities(observe=True),
    session_end=capability.SessionEndCapabilities(observe=True),
)
assert capabilities.to_wire() == {
    "session.end": {"modes": ["observe"]},
    "tool.before": {"modes": ["observe"]},
}
```

The wire declarations are unchanged.
