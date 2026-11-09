import assert from 'node:assert/strict';
import test from 'node:test';
import {
  auditCommandExecution,
  buildArgvFromToolInput,
  compileToMcpTools,
  McpForgeServer,
  parseCliHelp,
  truncateCliOutput
} from '../src/index.js';

const SAMPLE_GIT_HELP = `usage: git [-v | --version] [-h | --help] [-C <path>]
           [--exec-path[=<path>]] [--html-path]

These are common Git commands used in various situations:

Commands:
   clone      Clone a repository into a new directory
   status     Show the working tree status
   reset      Reset current HEAD to the specified state
   rm         Remove files from the working tree and from the index

Options:
  -C <path>                 Run as if git was started in <path>
  -q, --quiet               Operate quietly and suppress progress reports
  -f, --force               Force destructive action [DESTRUCTIVE]
  --depth <NUM>             Create a shallow clone with a history truncated to NUM commits [default: 1]
  --color <WHEN>            Respect color settings [possible values: always, never, auto]
`;

test('parseCliHelp extracts subcommands, typed flags, defaults, and enums', () => {
  const spec = parseCliHelp('git', SAMPLE_GIT_HELP);
  assert.equal(spec.binaryName, 'git');
  assert.equal(spec.subcommands.length, 4);
  assert.equal(spec.subcommands[0].name, 'clone');
  assert.equal(spec.subcommands[3].name, 'rm');
  assert.equal(spec.subcommands[3].riskLevel, 'destructive');

  const depthOpt = spec.options.find((o) => o.name === 'depth');
  assert.ok(depthOpt, 'Expected --depth option to be parsed');
  assert.equal(depthOpt.type, 'number');
  assert.equal(depthOpt.defaultValue, 1);

  const colorOpt = spec.options.find((o) => o.name === 'color');
  assert.ok(colorOpt, 'Expected --color option to be parsed');
  assert.deepEqual(colorOpt.enumValues, ['always', 'never', 'auto']);

  const forceOpt = spec.options.find((o) => o.name === 'force');
  assert.ok(forceOpt);
  assert.equal(forceOpt.riskLevel, 'destructive');
});

test('compileToMcpTools generates valid MCP inputSchema and reconstructs safe argv', () => {
  const spec = parseCliHelp('git', SAMPLE_GIT_HELP);
  const tools = compileToMcpTools(spec);
  assert.equal(tools.length, 1);

  const tool = tools[0];
  assert.equal(tool.name, 'cli_git');
  assert.ok(tool.inputSchema.properties.subcommand);
  assert.ok(tool.inputSchema.properties.depth);
  assert.ok(tool.inputSchema.properties.dry_run);

  const argv = buildArgvFromToolInput(spec, {
    subcommand: 'clone',
    depth: 5,
    quiet: true,
    positional_args: ['https://example.com/repo.git']
  });

  assert.deepEqual(argv, ['clone', '--quiet', '--depth', '5', 'https://example.com/repo.git']);
});

test('auditCommandExecution blocks shell injection, destructive flags, and path traversal', () => {
  const safeRes = auditCommandExecution('git', ['status', '--quiet'], {
    allowedWorkingDir: '/home/user/repo'
  });
  assert.equal(safeRes.status, 'allow');
  assert.equal(safeRes.violations.length, 0);

  const injectionRes = auditCommandExecution('git', ['status; cat /etc/passwd'], {
    allowedWorkingDir: '/home/user/repo'
  });
  assert.equal(injectionRes.status, 'block');
  assert.ok(injectionRes.violations.some((v) => v.ruleId === 'FW002_SHELL_INJECTION'));
  assert.ok(injectionRes.violations.some((v) => v.ruleId === 'FW005_SENSITIVE_PATH'));

  const traversalRes = auditCommandExecution('git', ['-C', '../../etc', 'status'], {
    allowedWorkingDir: '/home/user/repo'
  });
  assert.equal(traversalRes.status, 'block');
  assert.ok(traversalRes.violations.some((v) => v.ruleId === 'FW006_PATH_TRAVERSAL'));

  const destructiveRes = auditCommandExecution('git', ['reset', '--hard']);
  assert.equal(destructiveRes.status, 'block');
  assert.ok(destructiveRes.violations.some((v) => v.ruleId === 'FW003_DESTRUCTIVE_FLAG'));
});

test('truncateCliOutput enforces token budget, preserves diagnostics, and scrubs secrets', () => {
  const lines: string[] = ['HEADER_COL1   HEADER_COL2   STATUS'];
  for (let i = 1; i <= 300; i++) {
    if (i === 150) {
      lines.push(`row_${i}   FATAL Exception: leaked token sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456`); // ship:allow-secret
    } else {
      lines.push(`row_${i}   normal_metric_value_${i}   OK`);
    }
  }

  const out = truncateCliOutput(lines.join('\n'), { maxTokens: 140 });
  assert.equal(out.truncated, true);
  assert.ok(out.finalEstimatedTokens <= 165, `Expected tokens <= 165, got ${out.finalEstimatedTokens}`);
  assert.equal(out.preservedDiagnosticsCount, 1);
  assert.equal(out.redactedSecretsCount, 1);
  assert.ok(out.content.includes('HEADER_COL1'));
  assert.ok(out.content.includes('FATAL Exception'));
  assert.ok(!out.content.includes('sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456')); // ship:allow-secret
  assert.ok(out.content.includes('row_300'));
});

test('McpForgeServer handles initialize, tools/list, dry_run, and firewall blocks over JSON-RPC', async () => {
  const spec = parseCliHelp('git', SAMPLE_GIT_HELP);
  const server = new McpForgeServer({ specs: [spec] });

  const initRes = await server.handleRequest({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize'
  });
  assert.ok(initRes?.result);

  const listRes = await server.handleRequest({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list'
  });
  const listedTools = (listRes?.result as { tools: unknown[] }).tools;
  assert.equal(listedTools.length, 1);

  const dryRunRes = await server.handleRequest({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'cli_git',
      arguments: {
        subcommand: 'status',
        quiet: true,
        dry_run: true
      }
    }
  });
  const dryRunText = (
    dryRunRes?.result as { content: Array<{ text: string }> }
  ).content[0].text;
  assert.ok(dryRunText.includes('DRY_RUN_PREVIEW'));
  assert.ok(dryRunText.includes('git status --quiet'));

  const blockedRes = await server.handleRequest({
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: {
      name: 'cli_git',
      arguments: {
        subcommand: 'rm',
        force: true,
        positional_args: ['/etc/shadow']
      }
    }
  });
  const blockedPayload = blockedRes?.result as {
    isError: boolean;
    content: Array<{ text: string }>;
  };
  assert.equal(blockedPayload.isError, true);
  assert.ok(blockedPayload.content[0].text.includes('BLOCKED_BY_MCP_FORGE_FIREWALL'));
});
