#!/usr/bin/env node
import { auditCommandExecution } from './firewall.js';
import { compileToMcpTools, parseCliHelp } from './parser.js';
import { introspectLocalBinary, McpForgeServer } from './server.js';
import { truncateCliOutput } from './truncator.js';

const SAMPLE_RG_HELP = `ripgrep 14.1.0
Andrew Gallant <jamslam@gmail.com>
ripgrep (rg) recursively searches the current directory for a regex pattern.

USAGE:
    rg [OPTIONS] PATTERN [PATH ...]

OPTIONS:
    -i, --ignore-case          Case insensitive search
    -v, --invert-match         Invert matching lines
    -w, --word-regexp          Only show matches surrounded by word boundaries
    -c, --count                Only show count of matching lines for each file
    -g, --glob <GLOB>...       Include or exclude files and directories
    -m, --max-count <NUM>      Limit the number of matching lines per file [default: 100]
    -C, --context <NUM>        Show NUM lines before and after each match
    -t, --type <TYPE>          Only search files matching TYPE
    --color <WHEN>             Controls when to use color [possible values: never, auto, always]
    --files-with-matches       Print only the paths with at least one match
`;

function printUsage(): void {
  console.log(`usage: mcp-forge <command> [args...]

commands:
  compile <bin...>       parse <bin> --help and print MCP tool JSON schema
  serve <bin...>         start MCP JSON-RPC 2.0 server on stdio
  audit <bin> [args...]  check command arguments against policy rules
  demo                   run local parser, policy check, and output truncation example

options:
  --max-tokens <num>     max token budget per tool call [default: 1500]
  --workspace <dir>      restrict file arguments to stay within <dir>
  -h, --help             show this help message`);
}

async function runDemo(): Promise<void> {
  console.log('# 1. compile rg --help -> MCP tool schema');
  const spec = parseCliHelp('rg', SAMPLE_RG_HELP);
  const tools = compileToMcpTools(spec);
  console.log(JSON.stringify(tools[0], null, 2));

  console.log('\n# 2. policy audit');
  const safeAudit = auditCommandExecution('rg', ['--ignore-case', '--max-count', '25', 'TODO', 'src/']);
  console.log('verdict:', safeAudit.status, '| cmd:', safeAudit.safeCommandPreview);

  const blockedAudit = auditCommandExecution('rg', ['--ignore-case', 'root; rm -rf /', '/etc/shadow'], {
    allowedWorkingDir: '/workspace/project'
  });
  console.log('verdict:', blockedAudit.status, '| score:', blockedAudit.riskScore);
  console.log('violations:', JSON.stringify(blockedAudit.violations, null, 2));

  console.log('\n# 3. output truncation & credential masking');
  const noisyLines: string[] = [
    'PID   USER     TIME  COMMAND',
    '1001  node     0:04  node server.js --api-key=sk-proj-1234567890abcdefghijklmnop'
  ];
  for (let i = 2; i <= 200; i++) {
    if (i === 95) {
      noisyLines.push(`${1000 + i}  worker   0:12  [ERROR] FATAL UnhandledPromiseRejection: database pool exhausted`);
    } else {
      noisyLines.push(`${1000 + i}  worker   0:01  node worker-pool.js --shard=${i}`);
    }
  }
  const truncated = truncateCliOutput(noisyLines.join('\n'), { maxTokens: 120 });
  console.log(truncated.content);
  console.log('\nstats:', {
    originalLines: truncated.originalLines,
    originalEstimatedTokens: truncated.originalEstimatedTokens,
    finalEstimatedTokens: truncated.finalEstimatedTokens,
    preservedDiagnosticsCount: truncated.preservedDiagnosticsCount,
    redactedSecretsCount: truncated.redactedSecretsCount
  });
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    printUsage();
    return;
  }

  const subcommand = args[0];
  const rest = args.slice(1);

  if (subcommand === 'demo') {
    await runDemo();
    return;
  }

  if (subcommand === 'compile') {
    if (rest.length === 0) {
      console.error('mcp-forge: missing binary name (e.g. mcp-forge compile git rg)');
      process.exit(1);
    }
    const specs = [];
    for (const bin of rest) {
      if (bin.startsWith('-')) continue;
      specs.push(await introspectLocalBinary(bin));
    }
    const compiled = specs.flatMap((s) => compileToMcpTools(s));
    console.log(JSON.stringify({ tools: compiled }, null, 2));
    return;
  }

  if (subcommand === 'audit') {
    if (rest.length === 0) {
      console.error('mcp-forge: missing command to audit');
      process.exit(1);
    }
    const result = auditCommandExecution(rest[0], rest.slice(1));
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.status === 'block' ? 2 : 0);
  }

  if (subcommand === 'serve') {
    const binaries = rest.filter((a) => !a.startsWith('-'));
    if (binaries.length === 0) {
      console.error('mcp-forge: specify at least one binary to serve');
      process.exit(1);
    }
    const specs = [];
    for (const bin of binaries) {
      specs.push(await introspectLocalBinary(bin));
    }
    const server = new McpForgeServer({ specs });
    server.startStdio();
    return;
  }

  console.error(`mcp-forge: unknown command '${subcommand}' (see --help)`);
  process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
