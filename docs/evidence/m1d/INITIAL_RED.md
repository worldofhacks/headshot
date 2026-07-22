# M1d initial RED evidence

Recorded before the M1d Web/API/runtime implementation on 2026-07-21.

Command:

```text
/tmp/headshot-m1d-venv/bin/python -m pytest \
  tests/test_web_m1d.py tests/auth/test_m1d_api.py tests/test_runtime_m1d.py
```

Result: collection failed with the three expected missing integration boundaries:

- `ModuleNotFoundError: No module named 'agentforge.web'`
- `ModuleNotFoundError: No module named 'agentforge.api'`
- `ModuleNotFoundError: No module named 'agentforge.runner'`

This is the retained test-first failure. The dependency-only baseline immediately before
these tests was `766 passed, 3 skipped`.
