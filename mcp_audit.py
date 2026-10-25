#!/usr/bin/env python3
"""Offline auditor for MCP client configuration files.

Agents wired to MCP servers trust whatever the config says to run: package
names, launch commands, environment variables, remote URLs. A bad entry means
code executing at every launch or credentials sitting in plaintext. This tool
reads MCP client configs (mcp.json, claude_desktop_config.json, and similar
shapes) and reports risky entries. It never launches a server, never touches
the network, and cannot prove a config is safe - it is a static auditor for
human review.
"""

import argparse
import json
import os
import re
import sys

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}

SECRET_NAME_RE = re.compile(r"(key|token|secret|password|passwd|credential)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"^(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)")
PLACEHOLDER_RE = re.compile(r"^(\$\{.*\}|\$[A-Z_]+|<.*>|\.\.\.|YOUR[_-].*|changeme|placeholder|xxx+)$",
                            re.IGNORECASE)
SHELL_COMMANDS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}
RUNNER_COMMANDS = {"npx", "uvx", "bunx", "pipx"}
BROAD_ARG_RE = re.compile(r"^(--allow-all|--allow-\*|--no-sandbox|--dangerously[a-z-]*)$")
ROOT_PATH_RE = re.compile(r"^(/|~|~/.?|[A-Za-z]:\\?)$")
FETCH_EXEC_RE = re.compile(r"(curl|wget)\b[^|]*(\||&&|;)\s*(sh|bash|zsh|python|node)")


def finding(code, severity, server, detail):
    return {"code": code, "severity": severity, "server": server, "detail": detail}


def is_placeholder(value):
    return bool(PLACEHOLDER_RE.match(str(value).strip()))


PACKAGE_NAME_RE = re.compile(r"^(@[\w.-]+/)?[\w.-]+(@[^\s]+)?$")


def package_pin(arg):
    """Return (package, pinned) for a runner package argument like
    '@scope/name@1.2.3' or 'name'. Scoped packages carry the version after
    the second '@'. Positional paths like './docs' are not packages."""
    if arg.startswith("-") or not PACKAGE_NAME_RE.match(arg):
        return None
    if arg.startswith("@"):
        parts = arg.split("@")
        return (arg, len(parts) > 2 and bool(parts[-1]))
    return (arg, "@" in arg and bool(arg.split("@", 1)[1]))


def pkg_base(pkg):
    """'@scope/name@1.2.3' -> '@scope/name'; 'name@1.2.3' -> 'name'; 'name' -> 'name'."""
    if pkg.startswith("@"):
        head, _, rest = pkg.partition("/")
        return head + "/" + rest.split("@")[0] if rest else pkg
    return pkg.split("@")[0]


def audit_server(name, spec, findings):
    label = str(name)
    if not isinstance(spec, dict):
        findings.append(finding("bad-entry", "error", label,
                                "server entry is not an object"))
        return findings
    # Remote servers: tool definitions arrive over the network at runtime.
    url = spec.get("url") or spec.get("serverUrl")
    if url:
        url = str(url)
        if url.startswith("http://"):
            host = re.sub(r"^http://", "", url).split("/")[0].split(":")[0]
            if host in ("localhost", "127.0.0.1", "::1"):
                findings.append(finding("remote-server", "info", label,
                                        "remote server over local http: %s" % url))
            else:
                findings.append(finding("insecure-remote", "error", label,
                                        "remote server over plaintext http: %s - "
                                        "tool definitions arrive unauthenticated" % url))
        elif url.startswith("https://"):
            findings.append(finding("remote-server", "info", label,
                                    "remote server: %s - its operator supplies the tool "
                                    "definitions your agent will trust" % url))
        else:
            findings.append(finding("bad-entry", "error", label,
                                    "unrecognized server URL scheme: %s" % url))
        return findings
    command = str(spec.get("command", ""))
    args = [str(a) for a in (spec.get("args") or [])]
    env = spec.get("env") or {}
    if not command:
        findings.append(finding("bad-entry", "error", label,
                                "no command or url - entry cannot launch anything"))
        return findings
    base = os.path.basename(command)
    if base in SHELL_COMMANDS:
        findings.append(finding("shell-wrapper", "warning", label,
                                "launches through a shell ('%s') - the real command is an "
                                "opaque string that is harder to audit" % base))
        joined = " ".join(args)
        if FETCH_EXEC_RE.search(joined):
            findings.append(finding("fetch-and-run", "error", label,
                                    "downloads and executes code at launch: %s" % joined[:120]))
    if base in RUNNER_COMMANDS:
        pkgs = [p for p in (package_pin(a) for a in args) if p]
        for pkg, pinned in pkgs:
            if pinned:
                findings.append(finding("pinned-package", "info", label,
                                        "%s runs '%s' at a pinned version" % (base, pkg)))
            else:
                findings.append(finding("unpinned-package", "warning", label,
                                        "%s runs '%s' with no version pin - resolves to "
                                        "whatever is newest at every launch" % (base, pkg)))
    for a in args:
        if BROAD_ARG_RE.match(a):
            findings.append(finding("broad-privilege", "warning", label,
                                    "argument '%s' disables isolation or grants blanket access" % a))
        if ROOT_PATH_RE.match(a):
            findings.append(finding("broad-privilege", "warning", label,
                                    "grants access to a root/home-wide path '%s'" % a))
    if isinstance(env, dict):
        for key, value in env.items():
            value = str(value)
            if is_placeholder(value):
                continue
            if SECRET_VALUE_RE.match(value):
                findings.append(finding("inline-secret", "error", label,
                                        "env '%s' holds a credential-shaped value in "
                                        "plaintext" % key))
            elif SECRET_NAME_RE.search(str(key)) and len(value) >= 8:
                findings.append(finding("inline-secret", "warning", label,
                                        "env '%s' is named like a credential and carries a "
                                        "non-placeholder value" % key))
    return findings


def audit_config(path):
    findings = []
    try:
        with open(path, errors="replace") as f:
            config = json.load(f)
    except FileNotFoundError:
        return [finding("bad-config", "error", path, "file not found")]
    except json.JSONDecodeError as e:
        return [finding("bad-config", "error", path, "not valid JSON: %s" % e)]
    if not isinstance(config, dict):
        return [finding("bad-config", "error", path, "top level is not an object")]
    servers = config.get("mcpServers") or config.get("servers")
    if not isinstance(servers, dict) or not servers:
        return [finding("bad-config", "error", path,
                        "no 'mcpServers' (or 'servers') map with entries")]
    seen_packages = {}
    for name, spec in servers.items():
        audit_server(name, spec, findings)
        if isinstance(spec, dict):
            args = [str(a) for a in (spec.get("args") or [])]
            for a in args:
                pin = package_pin(a)
                if pin:
                    pkg = pkg_base(pin[0])
                    if pkg in seen_packages and seen_packages[pkg] != str(name):
                        findings.append(finding(
                            "duplicate-server", "info", str(name),
                            "package '%s' also registered as server '%s'"
                            % (pkg, seen_packages[pkg])))
                    seen_packages[pkg] = str(name)
    return findings


def collect_files(path):
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        out = []
        for root, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.endswith(".json"):
                    out.append(os.path.join(root, name))
        return out
    return []


def run(path):
    files = collect_files(path)
    if not files:
        return [finding("no-input", "error", path, "path not found or no .json files")]
    findings = []
    for f in files:
        findings.extend(audit_config(f))
    return findings


def filter_severity(findings, min_severity):
    floor = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER[f["severity"]] >= floor]


def format_text(findings):
    return "\n".join("%-7s %-18s %-22s %s" % (
        f["severity"].upper(), f["code"], f["server"], f["detail"])
        for f in findings)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Static audit of MCP client config files.")
    parser.add_argument("path", help="config file or directory of .json configs")
    parser.add_argument("--min-severity", choices=["info", "warning", "error"], default="info")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)

    findings = filter_severity(run(args.path), args.min_severity)
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif findings:
        print(format_text(findings))
    else:
        print("no findings")
    return 1 if any(f["severity"] == "error" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
