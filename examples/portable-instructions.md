# Platform-specific setup

## Bash (Linux or WSL)

```bash
export MODE=dev
. .venv/bin/activate
python -m unittest
```

## PowerShell (Windows)

```powershell
$env:MODE = "dev"
. .\.venv\Scripts\Activate.ps1
python -m unittest
```

## Command Prompt (Windows)

```cmd
set "MODE=dev"
call .venv\Scripts\activate.bat
python -m unittest
```
