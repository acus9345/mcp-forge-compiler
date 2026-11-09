export type CliOptionType = 'boolean' | 'string' | 'number' | 'array';

export interface ParsedCliOption {
  /** Primary property name in camelCase or snake_case for MCP JSON Schema */
  name: string;
  /** Long flag (e.g. "--output" or "--max-depth") */
  longFlag?: string;
  /** Short flag (e.g. "-o" or "-d") */
  shortFlag?: string;
  /** Value placeholder if the option accepts an argument (e.g. "<FILE>", "NUM", "FORMAT") */
  argName?: string;
  /** Inferred JSON Schema primitive type */
  type: CliOptionType;
  /** Enum choices if detected in help description or placeholder */
  enumValues?: string[];
  /** Default value if mentioned in description */
  defaultValue?: string | number | boolean;
  /** Cleaned human-readable description */
  description: string;
  /** Whether the flag is marked as required */
  required: boolean;
  /** Whether this flag is potentially destructive or mutating */
  riskLevel: 'safe' | 'caution' | 'destructive';
}

export interface ParsedSubcommand {
  name: string;
  aliases: string[];
  description: string;
  riskLevel: 'safe' | 'caution' | 'destructive';
}

export interface ParsedCliSpec {
  binaryName: string;
  version?: string;
  summary: string;
  usagePatterns: string[];
  subcommands: ParsedSubcommand[];
  options: ParsedCliOption[];
  examples: string[];
}

export interface McpJsonSchemaProperty {
  type: string;
  description: string;
  default?: string | number | boolean;
  enum?: string[];
  items?: { type: string };
}

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, McpJsonSchemaProperty>;
    required?: string[];
    additionalProperties?: boolean;
  };
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
}

export type FirewallVerdictStatus = 'allow' | 'dry_run_required' | 'block';

export interface FirewallPolicy {
  /** Block shell metacharacters & command chaining if raw strings are checked */
  blockShellMetacharacters: boolean;
  /** Restrict file arguments to stay within allowedWorkingDir */
  allowedWorkingDir?: string;
  /** Block known destructive flags (--force, --delete, --hard, -rf, --drop, etc.) */
  blockDestructiveFlags: boolean;
  /** Custom blocked flags or subcommands */
  customBlockedTokens?: string[];
  /** Force dry-run preview before mutating commands */
  enforceDryRunOnCaution: boolean;
  /** Redact secrets/tokens from environment and stdout */
  scrubSecrets: boolean;
}

export interface FirewallViolation {
  ruleId: string;
  severity: 'medium' | 'high' | 'critical';
  token: string;
  reason: string;
  remediation: string;
}

export interface FirewallAuditResult {
  status: FirewallVerdictStatus;
  binary: string;
  argv: string[];
  riskScore: number;
  violations: FirewallViolation[];
  safeCommandPreview: string;
}

export interface TruncatorOptions {
  /** Maximum token budget (approx 4 chars = 1 token) */
  maxTokens: number;
  /** Ratio of budget allocated to head vs tail (0.0 to 1.0, default 0.65) */
  headRatio?: number;
  /** Preserve error/warning/stack-trace lines from middle section */
  preserveDiagnosticLines?: boolean;
  /** Scrub API keys, Bearer tokens, AWS keys, and PEM blocks */
  scrubSecrets?: boolean;
}

export interface TruncatedOutput {
  content: string;
  originalBytes: number;
  originalLines: number;
  originalEstimatedTokens: number;
  finalEstimatedTokens: number;
  truncated: boolean;
  omittedLines: number;
  preservedDiagnosticsCount: number;
  redactedSecretsCount: number;
  detectedFormat: 'json' | 'table' | 'log' | 'text';
}
