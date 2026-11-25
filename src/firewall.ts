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

const CAUTION_TOKENS = new Set([
  'write',
  'edit',
  'modify',
  'update',
  'push',
  'deploy',
  'publish',
  'install',
  'exec',
  'run',
  'apply',
  'commit',
  'mutate',
  '--write',
  '--edit',
  '--modify',
  '--update',
  '--push',
  '--deploy',
  '--publish',
  '--install',
  '--apply',
  '--commit'
]);

const SENSITIVE_PATH_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  { label: '/etc/passwd', pattern: /\/etc\/passwd(?=$|[\s'"/:;])/i },
  { label: '/etc/shadow', pattern: /\/etc\/shadow(?=$|[\s'"/:;])/i },
  { label: '/etc/sudoers', pattern: /\/etc\/sudoers(?=$|[\s'"/:;])/i },
  { label: '/root', pattern: /(?:^|[\s'"=:])\/root(?=$|[/\s'":;])/i },
  { label: '/.ssh', pattern: /\/\.ssh(?=$|[/\s'":;])/i },
  { label: '.ssh/id_rsa', pattern: /\.ssh\/id_rsa(?=$|[\s'"/:;.])/i },
  { label: '.ssh/id_ed25519', pattern: /\.ssh\/id_ed25519(?=$|[\s'"/:;.])/i },
  { label: '.aws/credentials', pattern: /\.aws\/credentials(?=$|[\s'"/:;])/i },
  { label: '.env', pattern: /(?:^|[\/\s'"=:])\.env(?:\.[a-z0-9_-]+)?(?=$|[\s'"/:;])/i },
  { label: '/proc/self/environ', pattern: /\/proc\/self\/environ(?=$|[\s'"/:;])/i }
];

function isWindowsDriveOrUnc(p: string): boolean {
  return /^[a-zA-Z]:/.test(p) || p.startsWith('\\\\') || /^\\[^\\]*[\\/]/.test(p);
}

function isRelativeEscape(rel: string): boolean {
  return (
    rel === '..' ||
    rel.startsWith('../') ||
    rel.startsWith('..\\') ||
    path.isAbsolute(rel) ||
    isWindowsDriveOrUnc(rel)
  );
}

function extractPathCandidates(token: string): string[] {
  const candidates: string[] = [];
  const eqIndex = token.indexOf('=');
  if (token.startsWith('-') && eqIndex > 0) {
    const val = token.slice(eqIndex + 1);
    if (val) candidates.push(val);
  } else if (/^-[a-zA-Z]/.test(token) && token.length > 2 && !token.startsWith('--')) {
    // Handle attached short option value such as -C../../etc or -C/etc
    const attached = token.slice(2);
    if (attached.includes('..') || attached.startsWith('/') || attached.startsWith('~') || isWindowsDriveOrUnc(attached)) {
      candidates.push(attached);
    }
  } else {
    candidates.push(token);
  }
  return candidates;
}

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

  // 1. Check binary name itself (cross-platform: strip path & executable extension)
  const baseBinary = path.posix
    .basename(binary.replace(/\\/g, '/'))
    .toLowerCase()
    .replace(/\.(exe|cmd|bat|com|ps1|sh)$/, '');
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
      const lowerFlag = normalizedFlag.toLowerCase();
      const isDestructiveLongFlag =
        normalizedFlag.startsWith('--') && DESTRUCTIVE_FLAG_SET.has(lowerFlag);
      if (
        isDestructiveLongFlag ||
        DESTRUCTIVE_FLAG_SET.has(normalizedFlag) ||
        DESTRUCTIVE_SUBCOMMANDS.has(lowerFlag)
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
    for (const sensitive of SENSITIVE_PATH_PATTERNS) {
      if (sensitive.pattern.test(normalizedToken)) {
        violations.push({
          ruleId: 'FW005_SENSITIVE_PATH',
          severity: 'critical',
          token,
          reason: `Argument references sensitive credential or system path '${sensitive.label}'.`,
          remediation: 'Restrict file operations to non-sensitive project files.'
        });
        riskScore += 95;
        break;
      }
    }

    // 6. Path traversal outside allowedWorkingDir
    if (mergedPolicy.allowedWorkingDir) {
      const resolvedRoot = path.resolve(mergedPolicy.allowedWorkingDir);
      for (const candidate of extractPathCandidates(token)) {
        const looksLikePath =
          candidate.includes('..') ||
          candidate.startsWith('/') ||
          candidate === '~' ||
          candidate.startsWith('~/') ||
          candidate.startsWith('~\\') ||
          isWindowsDriveOrUnc(candidate);
        if (!looksLikePath) continue;

        const isHomeEscape =
          candidate === '~' || candidate.startsWith('~/') || candidate.startsWith('~\\');
        const isCrossPlatformRoot =
          isWindowsDriveOrUnc(candidate) && !isWindowsDriveOrUnc(resolvedRoot);

        let outsideWorkspace = isHomeEscape || isCrossPlatformRoot;
        if (!outsideWorkspace) {
          const resolvedTarget = path.resolve(resolvedRoot, candidate);
          const rel = path.relative(resolvedRoot, resolvedTarget);
          outsideWorkspace = isRelativeEscape(rel);
        }

        if (outsideWorkspace) {
          violations.push({
            ruleId: 'FW006_PATH_TRAVERSAL',
            severity: 'critical',
            token,
            reason: `Path '${token}' resolves outside the sandboxed workspace root (${resolvedRoot}).`,
            remediation: `Keep all file paths inside '${resolvedRoot}'.`
          });
          riskScore += 80;
          break;
        }
      }
    }

    // 7. Caution / mutating action check when dry-run enforcement is enabled
    if (mergedPolicy.enforceDryRunOnCaution) {
      const normalizedCaution = token.split('=')[0].trim().toLowerCase();
      if (CAUTION_TOKENS.has(normalizedCaution)) {
        violations.push({
          ruleId: 'FW007_CAUTION_MUTATION',
          severity: 'medium',
          token,
          reason: `Argument '${normalizedCaution}' may mutate external or repository state; dry-run preview required.`,
          remediation: 'Inspect the dry-run preview and rerun with enforceDryRunOnCaution disabled to execute.'
        });
        riskScore += 25;
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
