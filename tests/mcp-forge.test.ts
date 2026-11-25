import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import {
  auditCommandExecution,
  buildArgvFromToolInput,
  compileToMcpTools,
  McpForgeServer,
  parseCliHelp,
  truncateCliOutput
} from '../src/index.js';

const execFileAsync = promisify(execFile);

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

test('parseCliHelp parses short-arg, variadic array, [=arg], --[no-]flag, and short boolean before uppercase word', () => {
  const help = `tool 2.0.0
Usage: tool [OPTIONS]

Options:
  -C <path>                 Run as if started in <path>
  -g, --glob <GLOB>...      Include or exclude files and directories
  --exec-path[=<path>]      Override execution path
  --[no-]verbose            Enable verbose logging
  -j  JSON output format
`;
  const spec = parseCliHelp('tool', help);

  const cOpt = spec.options.find((o) => o.name === 'c');
  assert.ok(cOpt, 'Expected -C <path> to be parsed');
  assert.equal(cOpt.shortFlag, '-C');
  assert.equal(cOpt.type, 'string');

  const globOpt = spec.options.find((o) => o.name === 'glob');
  assert.ok(globOpt, 'Expected -g, --glob <GLOB>... to be parsed');
  assert.equal(globOpt.type, 'array');

  const execPathOpt = spec.options.find((o) => o.name === 'exec_path');
  assert.ok(execPathOpt, 'Expected --exec-path[=<path>] to be parsed');
  assert.equal(execPathOpt.type, 'string');

  const verboseOpt = spec.options.find((o) => o.name === 'verbose');
  assert.ok(verboseOpt, 'Expected --[no-]verbose to be parsed');
  assert.equal(verboseOpt.longFlag, '--verbose');
  assert.equal(verboseOpt.type, 'boolean');

  const jOpt = spec.options.find((o) => o.name === 'j');
  assert.ok(jOpt, 'Expected -j  JSON output format to be parsed');
  assert.equal(jOpt.type, 'boolean');

  const argv = buildArgvFromToolInput(spec, {
    c: 'sub',
    glob: ['*.ts', null, undefined],
    verbose: true,
    j: true
  });
  assert.deepEqual(argv, ['-C', 'sub', '--glob', '*.ts', '--verbose', '-j']);
});

test('auditCommandExecution enforces Windows binaries/paths, flag=value traversal, tilde escape, sensitive paths, and enforceDryRunOnCaution', () => {
  const winBin = auditCommandExecution('C:\\Windows\\System32\\rm.exe', ['file.txt']);
  assert.equal(winBin.status, 'block');
  assert.ok(winBin.violations.some((v) => v.ruleId === 'FW001_DESTRUCTIVE_BINARY'));

  const upperForce = auditCommandExecution('git', ['push', '--FORCE']);
  assert.equal(upperForce.status, 'block');
  assert.ok(upperForce.violations.some((v) => v.ruleId === 'FW003_DESTRUCTIVE_FLAG'));

  const fixedStrings = auditCommandExecution('rg', ['-F', 'pattern']);
  assert.equal(fixedStrings.status, 'allow');

  const safeEnvFilename = auditCommandExecution('rg', ['TODO', 'src/app.environment.ts', '/var/rootless']);
  assert.equal(safeEnvFilename.status, 'allow');

  const dotEnv = auditCommandExecution('cat', ['.env.local']);
  assert.equal(dotEnv.status, 'block');
  assert.ok(dotEnv.violations.some((v) => v.ruleId === 'FW005_SENSITIVE_PATH'));

  const tildeEscape = auditCommandExecution('rg', ['~/secret'], {
    allowedWorkingDir: '/home/user/repo'
  });
  assert.equal(tildeEscape.status, 'block');
  assert.ok(tildeEscape.violations.some((v) => v.ruleId === 'FW006_PATH_TRAVERSAL'));

  const flagEqTraversal = auditCommandExecution('git', ['--work-tree=../../etc', 'status'], {
    allowedWorkingDir: '/home/user/repo'
  });
  assert.equal(flagEqTraversal.status, 'block');
  assert.ok(flagEqTraversal.violations.some((v) => v.ruleId === 'FW006_PATH_TRAVERSAL'));

  const winDriveTraversal = auditCommandExecution('rg', ['foo', 'C:\\Windows\\System32\\drivers\\etc\\hosts'], {
    allowedWorkingDir: '/home/user/repo'
  });
  assert.equal(winDriveTraversal.status, 'block');
  assert.ok(winDriveTraversal.violations.some((v) => v.ruleId === 'FW006_PATH_TRAVERSAL'));

  const dryRunCaution = auditCommandExecution('git', ['commit', '-m', 'update'], {
    enforceDryRunOnCaution: true
  });
  assert.equal(dryRunCaution.status, 'dry_run_required');
  assert.ok(dryRunCaution.violations.some((v) => v.ruleId === 'FW007_CAUTION_MUTATION'));
});

test('truncateCliOutput stays within budget with multiple diagnostics, handles single-line output, and scrubs PEM keys', () => {
  const lines: string[] = ['START'];
  for (let i = 1; i <= 200; i++) {
    if (i >= 50 && i <= 60) {
      lines.push(`ERROR line ${i}: something failed in worker ${i} with extra diagnostic detail`);
    } else {
      lines.push(`line ${i} normal output payload`);
    }
  }
  lines.push('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtestkeydata\n-----END RSA PRIVATE KEY-----');
  lines.push('END');

  const out = truncateCliOutput(lines.join('\n'), { maxTokens: 150 });
  assert.equal(out.truncated, true);
  assert.ok(out.finalEstimatedTokens <= 165, `Expected tokens <= 165, got ${out.finalEstimatedTokens}`);
  assert.ok(out.preservedDiagnosticsCount >= 1);
  assert.equal(out.redactedSecretsCount, 1);
  assert.ok(!out.content.includes('MIIEowIBAAKCAQEAtestkeydata'));

  const hugeSingleLine = 'A'.repeat(2000) + 'MIDDLE_SECRET' + 'Z'.repeat(2000);
  const singleOut = truncateCliOutput(hugeSingleLine, { maxTokens: 120 });
  assert.equal(singleOut.truncated, true);
  assert.ok(singleOut.content.startsWith('AAAA'));
  assert.ok(singleOut.content.endsWith('ZZZZ'));
  assert.ok(singleOut.content.includes('omitted middle of 1 long line'));
});

test('McpForgeServer validates malformed JSON-RPC requests and executes inside allowedWorkingDir', async () => {
  const nodeSpec = parseCliHelp(process.execPath, 'Usage: node [options]\nOptions:\n  -e, --eval <SCRIPT>   Evaluate script\n');
  const tmpDir = os.tmpdir();
  const server = new McpForgeServer({
    specs: [nodeSpec],
    firewallPolicy: { allowedWorkingDir: tmpDir }
  });

  const invalidReq = await server.handleRequest(null as unknown as { jsonrpc: '2.0'; method: string });
  assert.equal(invalidReq?.error?.code, -32600);

  const invalidParams = await server.handleRequest({
    jsonrpc: '2.0',
    id: 10,
    method: 'tools/call',
    params: {
      name: nodeSpec ? `cli_${process.execPath.replace(/[^a-zA-Z0-9_-]/g, '_')}` : '',
      arguments: ['not-an-object'] as unknown as Record<string, unknown>
    }
  });
  assert.equal(invalidParams?.error?.code, -32602);

  const cwdRes = await server.handleRequest({
    jsonrpc: '2.0',
    id: 11,
    method: 'tools/call',
    params: {
      name: `cli_${process.execPath.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
      arguments: {
        eval: 'console.log(process.cwd())'
      }
    }
  });
  const text = (cwdRes?.result as { content: Array<{ text: string }> }).content[0].text.trim();
  assert.equal(path.resolve(text), path.resolve(tmpDir));
});

test('CLI audit and serve honor --workspace and --max-tokens flags', async () => {
  const cliPath = path.resolve('dist/src/cli.js');

  await assert.rejects(
    () => execFileAsync(process.execPath, [cliPath, 'audit', '--workspace', '/home/user/repo', 'git', '-C', '../../etc', 'status']),
    (err: unknown) => {
      const execErr = err as { code?: number; stdout?: string };
      assert.equal(execErr.code, 2);
      assert.ok((execErr.stdout || '').includes('FW006_PATH_TRAVERSAL'));
      return true;
    }
  );

  const auditHelp = await execFileAsync(process.execPath, [cliPath, 'audit', 'git', '--help']);
  const auditPayload = JSON.parse(auditHelp.stdout) as { status: string; argv: string[] };
  assert.equal(auditPayload.status, 'allow');
  assert.deepEqual(auditPayload.argv, ['--help']);

  await assert.rejects(
    () => execFileAsync(process.execPath, [cliPath, 'serve', '--max-tokens', 'not-a-number', process.execPath]),
    (err: unknown) => {
      const execErr = err as { code?: number; stderr?: string };
      assert.equal(execErr.code, 1);
      assert.ok((execErr.stderr || '').includes('--max-tokens'));
      return true;
    }
  );

  const serveProc = spawn(process.execPath, [
    cliPath,
    'serve',
    '--workspace',
    os.tmpdir(),
    '--max-tokens',
    '500',
    process.execPath
  ]);

  const responseLine = await new Promise<string>((resolve, reject) => {
    let buffer = '';
    serveProc.stdout.on('data', (chunk) => {
      buffer += chunk.toString();
      const idx = buffer.indexOf('\n');
      if (idx !== -1) {
        resolve(buffer.slice(0, idx));
      }
    });
    serveProc.on('error', reject);
    serveProc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) + '\n');
  });

  serveProc.kill();
  const parsed = JSON.parse(responseLine) as { result?: { tools?: Array<{ name: string }> } };
  assert.equal(parsed.result?.tools?.length, 1);
});
