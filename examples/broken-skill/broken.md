---
name: broken-example
description: A deliberately non-portable example used by the demo and tests.
---

# Setup in Windows PowerShell

```powershell
export MODE=dev
source scripts/bootstrap.sh
python - <<'PY'
print("setup")
PY
```

# Run under WSL

```bash
./scripts/setup.cmd --quiet
```
