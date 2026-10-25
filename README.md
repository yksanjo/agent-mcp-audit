# agent-mcp-audit

Offline auditor for MCP client configuration files.

Agents wired to MCP servers trust whatever the config says to run: package names, launch commands, environment variables, remote URLs. A bad entry means code executing at every launch or credentials sitting in plaintext. This tool reads MCP client configs (`mcp.json`, `claude_desktop_config.json`, and similar shapes) and reports risky entries with severity. It never launches a server, never touches the network.

## What it reports

| Code | Severity | Signal |
| --- | --- | --- |
| `inline-secret` | error / warning | env value matches a credential shape (error), or a credential-named variable holds a non-placeholder value (warning). Placeholders like `${VAR}`, `<your-key>`, `YOUR_KEY` are skipped |
| `insecure-remote` | error | remote server over plaintext http - tool definitions arrive unauthenticated (localhost http is info) |
| `fetch-and-run` | error | launch command downloads and executes code (curl piped to a shell) |
| `unpinned-package` | warning | npx/uvx/bunx/pipx runs a package with no version pin - resolves to whatever is newest at every launch |
| `shell-wrapper` | warning | launches through sh/bash/cmd - the real command is an opaque string |
| `broad-privilege` | warning | `--allow-all`-style flags or root/home-wide path arguments |
| `remote-server` | info | remote https server - its operator supplies the tool definitions your agent will trust |
| `pinned-package` | info | package pinned to a version (the baseline to aim for) |
| `duplicate-server` | info | same package registered under two server names |
| `bad-entry` / `bad-config` / `no-input` | error | malformed entries or files |

## Usage

```bash
python3 mcp_audit.py ~/.config/agent/mcp.json
python3 mcp_audit.py ./configs --min-severity warning
python3 mcp_audit.py mcp.json --format json
python3 demo.py
python3 -m unittest test_mcp_audit
```

Exit code is 1 when any reported finding is an error, else 0, so it can gate CI or a config-commit hook.

## Honest limits

- **A clean audit does not prove a config is safe.** A pinned, tidy server can still be malicious; this checks config shapes, not server code. Runtime scanners that actually launch and probe servers (e.g. Invariant's mcp-scan, Snyk's agent-scan) go further - this tool is the single-file, zero-install, offline slice.
- Credential detection is shape-based: it catches common token formats and credential-named variables, and misses rotated, split, or non-standard secrets.
- Version-pin parsing covers the common `npx -y pkg[@version]` shape; exotic runners or wrapper scripts may parse wrong in either direction.
- It cannot tell whether a broad privilege is intentional - filesystem servers legitimately need paths. Findings are for human review, not automatic verdicts.
- Demo configs are synthetic and invented; the token-shaped value is fake.

## License

MIT
