import { TruncatedOutput, TruncatorOptions } from './types.js';

const SECRET_REDACTION_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  {
    name: 'OpenAI / Anthropic / Sk-Key',
    regex: /\bsk-(?:proj-|ant-)?[a-zA-Z0-9_-]{16,}\b/g
  },
  {
    name: 'GitHub PAT',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g
  },
  {
    name: 'AWS Access Key',
    regex: /\bAKIA[0-9A-Z]{16}\b/g
  },
  {
    name: 'Bearer Token',
    regex: /Bearer\s+[A-Za-z0-9._~+/-]{20,}/gi
  },
  {
    name: 'Generic Secret Assignment',
    regex: /((?:api_key|apikey|secret|password|token|access_token)\s*[:=]\s*["']?)([A-Za-z0-9._~+/-]{12,})(["']?)/gi
  }
];

const DIAGNOSTIC_LINE_REGEX =
  /\b(error|exception|fatal|fail|failed|panic|traceback|caused by|syntaxerror|typeerror|referenceerror|warn|warning)\b/i;

/**
 * Estimates LLM token count (~4 characters per token heuristic).
 */
export function estimateTokens(text: string): number {
  if (!text) return 0;
  return Math.ceil(text.length / 4);
}

/**
 * Detects whether CLI output is JSON, ASCII/whitespace table, structured logs, or plain text.
 */
export function detectOutputFormat(text: string): 'json' | 'table' | 'log' | 'text' {
  const trimmed = text.trim();
  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      JSON.parse(trimmed);
      return 'json';
    } catch {
      // Fall through if partial JSON
    }
  }

  const lines = trimmed.split('\n').slice(0, 10);
  if (lines.length >= 2) {
    // Check for tabular header (ALL CAPS columns or pipe table)
    if (
      /^[A-Z0-9_\s-]{10,}$/.test(lines[0].trim()) &&
      /\s{2,}/.test(lines[0].trim())
    ) {
      return 'table';
    }
    if (lines[0].includes('|') && lines[1].includes('-')) {
      return 'table';
    }
  }

  if (
    lines.some((l) =>
      /^(\d{4}-\d{2}-\d{2}|\[?(INFO|WARN|ERROR|DEBUG)\]?)/i.test(l.trim())
    )
  ) {
    return 'log';
  }

  return 'text';
}

/**
 * Redacts API keys, tokens, and secrets from raw command output before sending to an LLM context window.
 */
export function scrubSecretsFromText(text: string): {
  scrubbedText: string;
  redactedCount: number;
} {
  let current = text;
  let redactedCount = 0;

  for (const rule of SECRET_REDACTION_PATTERNS) {
    current = current.replace(rule.regex, (...args) => {
      redactedCount++;
      if (rule.name === 'Generic Secret Assignment') {
        return `${args[1]}[REDACTED_BY_MCP_FORGE]${args[3] || ''}`;
      }
      if (rule.name === 'Bearer Token') {
        return 'Bearer [REDACTED_BY_MCP_FORGE]';
      }
      return `[REDACTED_${rule.name.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}]`;
    });
  }

  return { scrubbedText: current, redactedCount };
}

/**
 * Smartly truncates large CLI stdout/stderr to fit within an LLM token budget (`maxTokens`)
 * while preserving table headers, head rows, critical diagnostic/error lines from the middle, and tail summary lines.
 */
export function truncateCliOutput(
  rawText: string,
  options: TruncatorOptions
): TruncatedOutput {
  const headRatio = options.headRatio ?? 0.65;
  const preserveDiagnosticLines = options.preserveDiagnosticLines ?? true;
  const shouldScrub = options.scrubSecrets ?? true;

  const originalBytes = Buffer.byteLength(rawText, 'utf8');
  const detectedFormat = detectOutputFormat(rawText);

  const { scrubbedText, redactedCount } = shouldScrub
    ? scrubSecretsFromText(rawText)
    : { scrubbedText: rawText, redactedCount: 0 };

  const lines = scrubbedText.replace(/\r\n/g, '\n').split('\n');
  const originalLines = lines.length;
  const originalEstimatedTokens = estimateTokens(scrubbedText);

  if (originalEstimatedTokens <= options.maxTokens) {
    return {
      content: scrubbedText,
      originalBytes,
      originalLines,
      originalEstimatedTokens,
      finalEstimatedTokens: originalEstimatedTokens,
      truncated: false,
      omittedLines: 0,
      preservedDiagnosticsCount: 0,
      redactedSecretsCount: redactedCount,
      detectedFormat
    };
  }

  const maxChars = Math.max(120, options.maxTokens * 4);
  const bannerReserveChars = 260;
  const usableChars = Math.max(80, maxChars - bannerReserveChars);

  const headBudgetChars = Math.floor(usableChars * headRatio);
  const tailBudgetChars = usableChars - headBudgetChars;

  const headLines: string[] = [];
  let headChars = 0;
  let headIndex = 0;

  while (headIndex < lines.length && headChars + lines[headIndex].length + 1 <= headBudgetChars) {
    headLines.push(lines[headIndex]);
    headChars += lines[headIndex].length + 1;
    headIndex++;
  }

  // Ensure at least the first line (e.g. table header) is kept if possible
  if (headLines.length === 0 && lines.length > 0) {
    headLines.push(lines[0].slice(0, headBudgetChars));
    headIndex = 1;
  }

  const tailLines: string[] = [];
  let tailChars = 0;
  let tailIndex = lines.length - 1;

  while (
    tailIndex >= headIndex &&
    tailChars + lines[tailIndex].length + 1 <= tailBudgetChars
  ) {
    tailLines.unshift(lines[tailIndex]);
    tailChars += lines[tailIndex].length + 1;
    tailIndex--;
  }

  // Scan the omitted middle range [headIndex .. tailIndex] for high-signal error/diagnostic lines
  const diagnosticLines: string[] = [];
  const maxDiagnosticLines = 8;
  if (preserveDiagnosticLines && tailIndex >= headIndex) {
    for (let i = headIndex; i <= tailIndex; i++) {
      if (DIAGNOSTIC_LINE_REGEX.test(lines[i])) {
        diagnosticLines.push(`[line ${i + 1}] ${lines[i].slice(0, 180)}`);
        if (diagnosticLines.length >= maxDiagnosticLines) break;
      }
    }
  }

  const omittedLines = Math.max(0, tailIndex - headIndex + 1);
  const middleSummaryParts: string[] = [
    `... [mcp-forge Context Guard: omitted ${omittedLines} lines (${
      originalEstimatedTokens - options.maxTokens
    }+ excess tokens) to protect LLM context window | format=${detectedFormat}] ...`
  ];

  if (diagnosticLines.length > 0) {
    middleSummaryParts.push(
      `--- Preserved Diagnostic / Error Signals from omitted section (${diagnosticLines.length}) ---`,
      ...diagnosticLines,
      `--- End Preserved Signals ---`
    );
  }

  const finalSections = [
    ...headLines,
    ...middleSummaryParts,
    ...tailLines
  ];

  const finalContent = finalSections.join('\n');

  return {
    content: finalContent,
    originalBytes,
    originalLines,
    originalEstimatedTokens,
    finalEstimatedTokens: estimateTokens(finalContent),
    truncated: true,
    omittedLines,
    preservedDiagnosticsCount: diagnosticLines.length,
    redactedSecretsCount: redactedCount,
    detectedFormat
  };
}
