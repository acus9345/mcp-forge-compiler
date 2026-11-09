# mcp-forge

Wrap local CLI binaries (`git`, `rg`, `docker`, `kubectl`, internal scripts) as MCP tools over stdio without writing schema boilerplate or giving an agent raw shell access.

## The problem

If you want an MCP client (Claude Desktop, Cursor, etc.) to use a local CLI tool, you usually end up doing one of two things:

1. Hand-writing JSON Schema wrappers for every flag and subcommand.
2. Giving the model a raw `bash` tool and hoping it doesn't run `git reset --hard`, read `~/.ssh/id_rsa`, or dump 40,000 lines of log output into the context window.

`mcp-forge` parses `<binary> --help` on startup, exposes a typed MCP tool over stdio, runs commands through `execFile` (no shell interpolation), blocks risky flags/paths, and trims oversized output before returning it to the client.

## Usage

### 1. Run as an MCP stdio server

Add to `claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "local-cli": {
      "command": "npx",
      "args": ["-y", "mcp-forge-compiler", "serve", "git", "rg", "docker", "kubectl"]
    }
  }
}
```

### 2. Inspect generated JSON Schema

```bash
$ npx mcp-forge-compiler compile rg git
```

### 3. Check how a command is evaluated by the policy rules

```bash
$ npx mcp-forge-compiler audit git reset --hard
```

## How it works

- **`src/parser.ts`** — Runs `<binary> --help` and extracts subcommands, short/long flags, types (`boolean`, `number`, `string`, `array`), `enum` choices, and default values. Supports GNU, POSIX, Rust `clap`, Go `cobra`, and Python `argparse` output formats.
- **`src/firewall.ts`** — Checks `argv` before spawning the process:
  - `FW001`: Blocks destructive binaries (`rm`, `dd`, `mkfs`, `shred`, etc.)
  - `FW002`: Rejects shell metacharacters (`;`, `|`, `&`, `` ` ``, `$()`)
  - `FW003`: Blocks destructive flags (`--force`, `--hard`, `--delete`, `-rf`)
  - `FW005`: Blocks reads/writes to sensitive paths (`/etc/shadow`, `.ssh/id_rsa`, `.env`)
  - `FW006`: Enforces workspace path boundaries when `--workspace` is set
- **`src/truncator.ts`** — Keeps stdout/stderr within a token budget (`--max-tokens`, default `1500`). Keeps the header/top lines and bottom summary lines, pulls out `ERROR`/`FATAL` lines from the omitted middle section, and masks common credential patterns (`sk-proj-*`, `ghp_*`, `AKIA*`).
- **`src/server.ts`** — Newline-delimited JSON-RPC 2.0 server over `stdin`/`stdout` implementing `initialize`, `tools/list`, `tools/call`, and `ping`.

## Library API

```ts
import {
  parseCliHelp,
  compileToMcpTools,
  auditCommandExecution,
  truncateCliOutput
} from 'mcp-forge-compiler';

const spec = parseCliHelp('rg', helpOutput);
const [tool] = compileToMcpTools(spec);

const audit = auditCommandExecution('rg', ['--ignore-case', 'TODO', 'src/'], {
  allowedWorkingDir: '/workspace/app'
});

const out = truncateCliOutput(rawStdout, {
  maxTokens: 1200,
  preserveDiagnosticLines: true,
  scrubSecrets: true
});
```

## Development

```bash
npm run build
npm test
npm run demo
```

## License

MIT
