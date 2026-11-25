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
    name: 'PEM Private Key',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g
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
  const rawHeadRatio = options.headRatio ?? 0.65;
  const headRatio = Math.min(0.9, Math.max(0.1, Number.isFinite(rawHeadRatio) ? rawHeadRatio : 0.65));
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
  const bannerReserveChars = 170;
  const baseUsableChars = Math.max(80, maxChars - bannerReserveChars);

  // Reserve a bounded portion of usableChars for diagnostics if needed, then split remainder between head and tail
  const initialHeadBudget = Math.floor(baseUsableChars * headRatio);
  const initialTailBudget = baseUsableChars - initialHeadBudget;

  // Estimate initial head/tail split to locate omitted middle range for diagnostics
  let estHeadEnd = 0;
  let estHeadChars = 0;
  while (estHeadEnd < lines.length && estHeadChars + lines[estHeadEnd].length + 1 <= initialHeadBudget) {
    estHeadChars += lines[estHeadEnd].length + 1;
    estHeadEnd++;
  }
  if (estHeadEnd === 0 && lines.length > 0) estHeadEnd = 1;

  let estTailStart = lines.length - 1;
  let estTailChars = 0;
  while (estTailStart >= estHeadEnd && estTailChars + lines[estTailStart].length + 1 <= initialTailBudget) {
    estTailChars += lines[estTailStart].length + 1;
    estTailStart--;
  }

  const diagnosticLines: string[] = [];
  const maxDiagnosticLines = 8;
  const maxDiagnosticBudget = Math.floor(baseUsableChars * 0.45);
  let diagnosticChars = 0;
  if (preserveDiagnosticLines && estTailStart >= estHeadEnd) {
    const diagHeaderFooterChars = 95;
    for (let i = estHeadEnd; i <= estTailStart; i++) {
      if (DIAGNOSTIC_LINE_REGEX.test(lines[i])) {
        const entry = `[line ${i + 1}] ${lines[i].slice(0, 140)}`;
        if (
          diagnosticLines.length > 0 &&
          diagnosticChars + diagHeaderFooterChars + entry.length + 1 > maxDiagnosticBudget
        ) {
          break;
        }
        diagnosticLines.push(entry);
        diagnosticChars += entry.length + 1;
        if (diagnosticLines.length >= maxDiagnosticLines) break;
      }
    }
  }

  const diagOverhead = diagnosticLines.length > 0 ? diagnosticChars + 95 : 0;
  const usableChars = Math.max(60, baseUsableChars - diagOverhead);
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

  // Ensure at least the first line (e.g. table header or single giant line) is kept
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

  // If tail is empty because the last line itself exceeded tailBudgetChars (including single-line inputs)
  if (tailLines.length === 0 && tailBudgetChars >= 16) {
    if (tailIndex >= headIndex) {
      tailLines.push(lines[tailIndex].slice(-tailBudgetChars));
      tailIndex--;
    } else if (lines.length === 1 && lines[0].length > headBudgetChars) {
      tailLines.push(lines[0].slice(-tailBudgetChars));
    }
  }

  const omittedLines = Math.max(0, tailIndex - headIndex + 1);
  const omittedCharsNote =
    omittedLines === 0 && lines.length === 1
      ? `omitted middle of 1 long line`
      : `omitted ${omittedLines} lines`;
  const middleSummaryParts: string[] = [
    `... [mcp-forge Context Guard: ${omittedCharsNote} (${
      Math.max(1, originalEstimatedTokens - options.maxTokens)
    }+ excess tokens) | format=${detectedFormat}] ...`
  ];

  if (diagnosticLines.length > 0) {
    middleSummaryParts.push(
      `--- Preserved Diagnostic / Error Signals (${diagnosticLines.length}) ---`,
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
