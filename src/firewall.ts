import path from 'node:path';
import {
  FirewallAuditResult,
  FirewallPolicy,
  FirewallVerdictStatus,
  FirewallViolation
} from './types.js';

export const DEFAULT_FIREWALL_POLICY: FirewallPolicy = {
  blockShellMetacharacters: true,
  blockDestructiveFlags: true,
  enforceDryRunOnCaution: false,
  scrubSecrets: true
};

const SHELL_INJECTION_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /[;&|`$<>]/,
    reason: 'Contains shell metacharacters or command-chaining operators (; & | ` $ < >)'
  },
  {
    pattern: /\$\([^)]*\)/,
    reason: 'Contains command substitution $(...)'
  },
  {
    pattern: /\r|\n|\0/,
    reason: 'Contains newline or null-byte injection characters'
  }
];

const DESTRUCTIVE_FLAG_SET = new Set([
  '--delete',
  '--force',
  '-f',
  '-rf',
  '-fr',
  '--hard',
  '--no-preserve-root',
  '--prune',
  '--drop',
  '--wipe',
  '--destroy',
  '--purge',
  '--overwrite'
]);

const DESTRUCTIVE_SUBCOMMANDS = new Set([
  'rm',
  'rmdir',
  'dd',
  'mkfs',
  'shred',
  'drop',
  'destroy',
  'uninstall',
  'nuke',
  'format'
]);

const SENSITIVE_SYSTEM_PATHS = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/sudoers',
  '/root',
  '/.ssh',
  '.ssh/id_rsa',
  '.ssh/id_ed25519',
  '.aws/credentials',
  '.env',
  '/proc/self/environ'
];

/**
 * Formats an argv list into a human-readable POSIX shell preview with safe quoting.
 */
export function formatCommandPreview(binary: string, argv: string[]): string {
  const quoteArg = (arg: string): string => {
    if (/^[a-zA-Z0-9_./:@=-]+$/.test(arg)) return arg;
    return `'${arg.replace(/'/g, `'\\''`)}'`;
  };
  return [quoteArg(binary), ...argv.map(quoteArg)].join(' ');
}

/**
 * Audits a candidate CLI execution (`binary` + `argv`) against the Zero-Trust Agent Firewall.
 */
export function auditCommandExecution(
  binary: string,
  argv: string[],
  policy: Partial<FirewallPolicy> = {}
): FirewallAuditResult {
  const mergedPolicy: FirewallPolicy = { ...DEFAULT_FIREWALL_POLICY, ...policy };
  const violations: FirewallViolation[] = [];
  let riskScore = 0;

  // 1. Check binary name itself
  const baseBinary = path.basename(binary);
  if (DESTRUCTIVE_SUBCOMMANDS.has(baseBinary)) {
    violations.push({
      ruleId: 'FW001_DESTRUCTIVE_BINARY',
      severity: 'critical',
      token: binary,
      reason: `Binary '${baseBinary}' is classified as directly destructive to filesystem or disk state.`,
      remediation: 'Use a read-only inspection tool or execute manually outside the agent session.'
    });
    riskScore += 90;
  }

  for (const token of argv) {
    // 2. Shell metacharacter / command injection check
    if (mergedPolicy.blockShellMetacharacters) {
      for (const rule of SHELL_INJECTION_PATTERNS) {
        if (rule.pattern.test(token)) {
          violations.push({
            ruleId: 'FW002_SHELL_INJECTION',
            severity: 'critical',
            token,
            reason: rule.reason,
            remediation:
              'Pass plain arguments without shell chaining, pipes, or subshell expansion.'
          });
          riskScore += 85;
          break;
        }
      }
    }

    // 3. Destructive flag or subcommand check
    if (mergedPolicy.blockDestructiveFlags) {
      const normalizedFlag = token.split('=')[0].trim();
      if (
        DESTRUCTIVE_FLAG_SET.has(normalizedFlag) ||
        DESTRUCTIVE_SUBCOMMANDS.has(normalizedFlag.toLowerCase())
      ) {
        violations.push({
          ruleId: 'FW003_DESTRUCTIVE_FLAG',
          severity: 'high',
          token,
          reason: `Flag or subcommand '${normalizedFlag}' performs irreversible state mutation or deletion.`,
          remediation:
            'Remove the destructive flag or run with dry_run: true for human review.'
        });
        riskScore += 60;
      }
    }

    // 4. Custom blocked tokens
    if (mergedPolicy.customBlockedTokens?.includes(token)) {
      violations.push({
        ruleId: 'FW004_CUSTOM_POLICY',
        severity: 'high',
        token,
        reason: `Token '${token}' is explicitly blocked by workspace policy.`,
        remediation: 'Remove the restricted argument.'
      });
      riskScore += 60;
    }

    // 5. Sensitive system & credential file access check
    const normalizedToken = token.replace(/\\/g, '/');
    for (const sensitivePath of SENSITIVE_SYSTEM_PATHS) {
      if (
        normalizedToken === sensitivePath ||
        normalizedToken.endsWith(`/${sensitivePath}`) ||
        normalizedToken.includes(sensitivePath)
      ) {
        violations.push({
          ruleId: 'FW005_SENSITIVE_PATH',
          severity: 'critical',
          token,
          reason: `Argument references sensitive credential or system path '${sensitivePath}'.`,
          remediation: 'Restrict file operations to non-sensitive project files.'
        });
        riskScore += 95;
      }
    }

    // 6. Path traversal outside allowedWorkingDir
    if (mergedPolicy.allowedWorkingDir) {
      const looksLikePath =
        token.includes('..') || token.startsWith('/') || token.startsWith('~');
      if (looksLikePath && !token.startsWith('--')) {
        const resolvedRoot = path.resolve(mergedPolicy.allowedWorkingDir);
        const resolvedTarget = path.resolve(mergedPolicy.allowedWorkingDir, token);
        if (!resolvedTarget.startsWith(resolvedRoot + path.sep) && resolvedTarget !== resolvedRoot) {
          violations.push({
            ruleId: 'FW006_PATH_TRAVERSAL',
            severity: 'critical',
            token,
            reason: `Path '${token}' resolves outside the sandboxed workspace root (${resolvedRoot}).`,
            remediation: `Keep all file paths inside '${resolvedRoot}'.`
          });
          riskScore += 80;
        }
      }
    }
  }

  riskScore = Math.min(100, riskScore);

  let status: FirewallVerdictStatus = 'allow';
  if (violations.some((v) => v.severity === 'critical' || v.severity === 'high')) {
    status = 'block';
  } else if (mergedPolicy.enforceDryRunOnCaution && riskScore > 0) {
    status = 'dry_run_required';
  }

  return {
    status,
    binary,
    argv,
    riskScore,
    violations,
    safeCommandPreview: formatCommandPreview(binary, argv)
  };
}

/**
 * Produces a sanitized environment dictionary for child processes, stripping sensitive cloud/API tokens
 * so subprocesses cannot accidentally leak credentials in debug dumps.
 */
export function createSanitizedEnv(
  baseEnv: NodeJS.ProcessEnv = process.env
): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  const secretKeyPattern =
    /(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|AWS_SECRET|OPENAI_API|ANTHROPIC_API|GITHUB_TOKEN)/i;

  for (const [k, v] of Object.entries(baseEnv)) {
    if (!secretKeyPattern.test(k)) {
      clean[k] = v;
    }
  }
  return clean;
}
