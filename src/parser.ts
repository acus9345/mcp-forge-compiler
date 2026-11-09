import {
  CliOptionType,
  McpJsonSchemaProperty,
  McpToolDefinition,
  ParsedCliOption,
  ParsedCliSpec,
  ParsedSubcommand
} from './types.js';

const DESTRUCTIVE_KEYWORDS =
  /\b(delete|remove|destroy|purge|drop|wipe|kill|force|hard|prune|overwrite|reset|uninstall|rm)\b/i;
const CAUTION_KEYWORDS =
  /\b(write|edit|modify|update|push|deploy|publish|install|exec|run|apply|commit|mutate)\b/i;

const NUMBER_ARG_PATTERNS =
  /^(num|number|count|int|integer|port|lines|bytes|size|depth|timeout|seconds|ms|limit|threads|jobs|retries)$/i;

/**
 * Normalizes a CLI flag like `--max-depth` or `-n` into a clean JSON Schema property key (`max_depth`).
 */
export function flagToPropertyKey(longFlag?: string, shortFlag?: string, argName?: string): string {
  const raw = longFlag
    ? longFlag.replace(/^-+/, '').replace(/^\[no-\]/, '')
    : shortFlag
    ? shortFlag.replace(/^-+/, '')
    : argName || 'arg';
  return raw
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

/**
 * Infers the JSON Schema primitive type from an option's argument placeholder and description.
 */
export function inferOptionType(argName?: string, description: string = ''): {
  type: CliOptionType;
  enumValues?: string[];
  defaultValue?: string | number | boolean;
} {
  if (!argName) {
    return { type: 'boolean', defaultValue: false };
  }

  const cleanedArg = argName.replace(/^[<\[(]+|[>\])]+$/g, '').trim();

  // Check if placeholder itself is an enum list like "json|yaml|text"
  if (cleanedArg.includes('|') && !cleanedArg.includes(' ')) {
    const parts = cleanedArg.split('|').map((s) => s.trim()).filter(Boolean);
    if (parts.length >= 2) {
      return { type: 'string', enumValues: parts };
    }
  }

  // Check description for explicit choices e.g. [possible values: auto, always, never] or (choices: a, b, c)
  const enumMatch =
    description.match(/(?:possible values|choices|values|one of)\s*:\s*([a-zA-Z0-9_.,\s|-]+)/i) ||
    description.match(/\[(auto|always|never|[a-z0-9_-]+(?:\s*\|\s*[a-z0-9_-]+)+)\]/i);

  let enumValues: string[] | undefined;
  if (enumMatch) {
    const rawList = enumMatch[1];
    const items = rawList
      .split(/[,|]|\bor\b/)
      .map((s) => s.replace(/[\[\]()."']/g, '').trim())
      .filter((s) => s.length > 0 && s.length < 32 && !s.includes(' '));
    if (items.length >= 2) {
      enumValues = Array.from(new Set(items));
    }
  }

  // Extract default value if present: [default: 10] or (default: "utf8")
  let defaultValue: string | number | boolean | undefined;
  const defaultMatch = description.match(/(?:\[default:\s*([^\]]+)\]|\(default:\s*([^)]+)\))/i);
  if (defaultMatch) {
    const rawDef = (defaultMatch[1] || defaultMatch[2]).trim().replace(/^["']|["']$/g, '');
    if (rawDef === 'true') defaultValue = true;
    else if (rawDef === 'false') defaultValue = false;
    else if (!Number.isNaN(Number(rawDef)) && rawDef !== '') defaultValue = Number(rawDef);
    else defaultValue = rawDef;
  }

  // Check repeatable / array hints
  if (
    cleanedArg.endsWith('...') ||
    /\b(multiple|repeatable|comma-separated|list of)\b/i.test(description)
  ) {
    return { type: 'array', enumValues };
  }

  // Check numeric hints
  if (
    NUMBER_ARG_PATTERNS.test(cleanedArg) ||
    /\b(number of|maximum number|port number|timeout in|in milliseconds|in seconds|integer)\b/i.test(
      description
    )
  ) {
    return { type: 'number', defaultValue: typeof defaultValue === 'number' ? defaultValue : undefined };
  }

  return { type: 'string', enumValues, defaultValue };
}

/**
 * Classify risk level of a CLI flag or subcommand based on name and description.
 */
export function classifyRiskLevel(
  token: string,
  description: string
): 'safe' | 'caution' | 'destructive' {
  const combined = `${token} ${description}`;
  if (
    DESTRUCTIVE_KEYWORDS.test(combined) ||
    token === '--force' ||
    token === '--delete' ||
    token === '--hard' ||
    token === '--no-preserve-root' ||
    (token === '-f' && /\b(force|delete|remove|destroy|overwrite)\b/i.test(description))
  ) {
    return 'destructive';
  }
  if (CAUTION_KEYWORDS.test(combined)) {
    return 'caution';
  }
  return 'safe';
}

/**
 * Parses arbitrary CLI `--help` or man-page style output into a structured `ParsedCliSpec`.
 * Supports GNU, POSIX, Rust clap, Go cobra/flag, Python argparse/click, and custom CLI layouts.
 */
export function parseCliHelp(binaryName: string, helpText: string): ParsedCliSpec {
  const lines = helpText.replace(/\r\n/g, '\n').split('\n');

  const usagePatterns: string[] = [];
  const options: ParsedCliOption[] = [];
  const subcommands: ParsedSubcommand[] = [];
  const examples: string[] = [];
  const seenOptionKeys = new Set<string>();
  const seenSubcommands = new Set<string>();

  let version: string | undefined;
  let summary = '';
  let currentSection: 'preamble' | 'usage' | 'options' | 'commands' | 'examples' | 'other' =
    'preamble';

  // Regex for option lines:
  // Matches:
  //   -f, --flag <VAL>     Description
  //   --long-only=VALUE    Description
  //   -v                   Description
  const optionLineRegex =
    /^\s{1,12}(?:(-[a-zA-Z0-9?])(?:\s*,\s*|\s+))?(?:(--[a-zA-Z0-9][a-zA-Z0-9_.-]*))?(?:[=\s]+(<[^>]+>|\[[a-zA-Z0-9_|-]+\]|[A-Z0-9_|-]{2,}))?(?:\s{2,}|\t+)(.+)$/;

  // Secondary option line regex where description is on the NEXT indented line
  const optionHeaderOnlyRegex =
    /^\s{1,12}(?:(-[a-zA-Z0-9?])(?:\s*,\s*|\s+))?(--[a-zA-Z0-9][a-zA-Z0-9_.-]*)(?:[=\s]+(<[^>]+>|\[[a-zA-Z0-9_|-]+\]|[A-Z0-9_|-]{2,}))?\s*$/;

  // Subcommand line regex when inside a COMMANDS section:
  //   build, b     Compile the current package
  const subcommandLineRegex =
    /^\s{2,8}([a-zA-Z0-9][a-zA-Z0-9_-]*)(?:,\s*([a-zA-Z0-9_-]+))?\s{2,}(.+)$/;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    if (!trimmed) continue;

    // Detect version in first few lines
    if (i < 5 && !version) {
      const verMatch = trimmed.match(/\bv?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)\b/);
      if (verMatch && !trimmed.startsWith('-')) {
        version = verMatch[1];
      }
    }

    // Section headers
    if (/^(usage|synopsis)\s*:?/i.test(trimmed)) {
      currentSection = 'usage';
      const inlineUsage = trimmed.replace(/^(usage|synopsis)\s*:?\s*/i, '').trim();
      if (inlineUsage) usagePatterns.push(inlineUsage);
      continue;
    }

    if (/^(options|flags|global options|common options|arguments|optional arguments|named arguments)[\s:]*$/i.test(trimmed)) {
      currentSection = 'options';
      continue;
    }

    if (/^(commands|subcommands|available commands|main commands|core commands)[\s:]*$/i.test(trimmed)) {
      currentSection = 'commands';
      continue;
    }

    if (/^(examples|example usage)[\s:]*$/i.test(trimmed)) {
      currentSection = 'examples';
      continue;
    }

    if (/^[A-Z][A-Z0-9\s_-]{2,}:$/.test(trimmed)) {
      if (trimmed.toLowerCase().includes('option') || trimmed.toLowerCase().includes('flag')) {
        currentSection = 'options';
      } else if (trimmed.toLowerCase().includes('command')) {
        currentSection = 'commands';
      } else if (trimmed.toLowerCase().includes('example')) {
        currentSection = 'examples';
      } else {
        currentSection = 'other';
      }
      continue;
    }

    // Try matching an option line anywhere (many tools don't have explicit OPTIONS: headers)
    const optMatch = rawLine.match(optionLineRegex);
    if (optMatch && (optMatch[1] || optMatch[2])) {
      const shortFlag = optMatch[1]?.trim();
      const longFlag = optMatch[2]?.trim();
      const argName = optMatch[3]?.trim();
      let desc = optMatch[4].trim();

      // Check if subsequent lines are deeply indented continuations
      while (i + 1 < lines.length && /^\s{14,}\S/.test(lines[i + 1])) {
        desc += ' ' + lines[i + 1].trim();
        i++;
      }

      const name = flagToPropertyKey(longFlag, shortFlag, argName);
      if (name && !seenOptionKeys.has(name) && name !== 'help' && name !== 'version') {
        seenOptionKeys.add(name);
        const inferred = inferOptionType(argName, desc);
        options.push({
          name,
          longFlag,
          shortFlag,
          argName,
          type: inferred.type,
          enumValues: inferred.enumValues,
          defaultValue: inferred.defaultValue,
          description: desc,
          required: /\b(required|mandatory)\b/i.test(desc),
          riskLevel: classifyRiskLevel(longFlag || shortFlag || name, desc)
        });
      }
      continue;
    }

    // Multi-line option where description is on the next line (common in clap / cargo / ripgrep)
    const headerOnlyMatch = rawLine.match(optionHeaderOnlyRegex);
    if (headerOnlyMatch && i + 1 < lines.length && /^\s{6,}\S/.test(lines[i + 1])) {
      const shortFlag = headerOnlyMatch[1]?.trim();
      const longFlag = headerOnlyMatch[2]?.trim();
      const argName = headerOnlyMatch[3]?.trim();
      let desc = lines[i + 1].trim();
      i++;
      while (i + 1 < lines.length && /^\s{6,}\S/.test(lines[i + 1]) && !lines[i + 1].trim().startsWith('-')) {
        desc += ' ' + lines[i + 1].trim();
        i++;
      }
      const name = flagToPropertyKey(longFlag, shortFlag, argName);
      if (name && !seenOptionKeys.has(name) && name !== 'help' && name !== 'version') {
        seenOptionKeys.add(name);
        const inferred = inferOptionType(argName, desc);
        options.push({
          name,
          longFlag,
          shortFlag,
          argName,
          type: inferred.type,
          enumValues: inferred.enumValues,
          defaultValue: inferred.defaultValue,
          description: desc,
          required: /\b(required|mandatory)\b/i.test(desc),
          riskLevel: classifyRiskLevel(longFlag || shortFlag || name, desc)
        });
      }
      continue;
    }

    if (currentSection === 'usage') {
      if (trimmed.startsWith(binaryName) || /^\S+\s+\[/.test(trimmed)) {
        usagePatterns.push(trimmed);
        continue;
      }
    }

    if (currentSection === 'commands') {
      const cmdMatch = rawLine.match(subcommandLineRegex);
      if (cmdMatch && !cmdMatch[1].startsWith('-')) {
        const cmdName = cmdMatch[1].trim();
        const alias = cmdMatch[2]?.trim();
        const desc = cmdMatch[3].trim();
        if (!seenSubcommands.has(cmdName) && cmdName !== 'help') {
          seenSubcommands.add(cmdName);
          subcommands.push({
            name: cmdName,
            aliases: alias ? [alias] : [],
            description: desc,
            riskLevel: classifyRiskLevel(cmdName, desc)
          });
        }
        continue;
      }
    }

    if (currentSection === 'examples') {
      examples.push(trimmed);
      continue;
    }

    if (currentSection === 'preamble' && !summary && !trimmed.startsWith('-')) {
      summary = trimmed;
    }
  }

  if (!summary) {
    summary = `Auto-compiled CLI tool wrapper for ${binaryName}`;
  }

  return {
    binaryName,
    version,
    summary,
    usagePatterns,
    subcommands,
    options,
    examples
  };
}

/**
 * Compiles a `ParsedCliSpec` into one or more Model Context Protocol (MCP) Tool Definitions.
 * Always adds a universal `positional_args` fallback array and a `dry_run` safety boolean.
 */
export function compileToMcpTools(spec: ParsedCliSpec): McpToolDefinition[] {
  const properties: Record<string, McpJsonSchemaProperty> = {};
  const required: string[] = [];

  if (spec.subcommands.length > 0) {
    properties['subcommand'] = {
      type: 'string',
      enum: spec.subcommands.map((c) => c.name),
      description: `Subcommand to run: ${spec.subcommands
        .map((c) => `${c.name} (${c.description})`)
        .join('; ')}`
    };
  }

  for (const opt of spec.options) {
    const flagLabel = [opt.shortFlag, opt.longFlag].filter(Boolean).join(', ');
    const riskTag =
      opt.riskLevel === 'destructive'
        ? ' [DESTRUCTIVE RISK]'
        : opt.riskLevel === 'caution'
        ? ' [CAUTION]'
        : '';

    const prop: McpJsonSchemaProperty = {
      type: opt.type,
      description: `${opt.description} (CLI flag: ${flagLabel})${riskTag}`
    };

    if (opt.enumValues && opt.enumValues.length > 0) {
      prop.enum = opt.enumValues;
    }
    if (opt.defaultValue !== undefined) {
      prop.default = opt.defaultValue;
    }
    if (opt.type === 'array') {
      prop.items = { type: 'string' };
    }

    properties[opt.name] = prop;
    if (opt.required) {
      required.push(opt.name);
    }
  }

  properties['positional_args'] = {
    type: 'array',
    items: { type: 'string' },
    description: 'Positional arguments (e.g., target paths, patterns, or URLs) passed after flags.'
  };

  properties['dry_run'] = {
    type: 'boolean',
    default: false,
    description:
      'If true, validates arguments through the mcp-forge Security Firewall and returns the exact command preview without executing it.'
  };

  const hasDestructive =
    spec.options.some((o) => o.riskLevel === 'destructive') ||
    spec.subcommands.some((s) => s.riskLevel === 'destructive');

  const sanitizedBinary = spec.binaryName.replace(/[^a-zA-Z0-9_-]/g, '_');

  const mainTool: McpToolDefinition = {
    name: `cli_${sanitizedBinary}`,
    description: `${spec.summary}${spec.version ? ` (v${spec.version})` : ''}. Guarded by mcp-forge zero-trust firewall & context-window truncator.`,
    inputSchema: {
      type: 'object',
      properties,
      ...(required.length > 0 ? { required } : {}),
      additionalProperties: false
    },
    annotations: {
      title: `${spec.binaryName} CLI Tool`,
      readOnlyHint: !hasDestructive && !spec.options.some((o) => o.riskLevel === 'caution'),
      destructiveHint: hasDestructive,
      idempotentHint: !hasDestructive,
      openWorldHint: true
    }
  };

  return [mainTool];
}

/**
 * Converts structured MCP tool call arguments back into a safe argv array for `execFile`
 * (never invoking a shell).
 */
export function buildArgvFromToolInput(
  spec: ParsedCliSpec,
  input: Record<string, unknown>
): string[] {
  const argv: string[] = [];

  if (typeof input.subcommand === 'string' && input.subcommand.trim() !== '') {
    argv.push(input.subcommand.trim());
  }

  for (const opt of spec.options) {
    const val = input[opt.name];
    if (val === undefined || val === null || val === false) continue;

    const flag = opt.longFlag || opt.shortFlag;
    if (!flag) continue;

    if (opt.type === 'boolean') {
      if (val === true) {
        argv.push(flag);
      }
    } else if (opt.type === 'array' && Array.isArray(val)) {
      for (const item of val) {
        argv.push(flag, String(item));
      }
    } else {
      argv.push(flag, String(val));
    }
  }

  if (Array.isArray(input.positional_args)) {
    for (const pos of input.positional_args) {
      if (pos !== undefined && pos !== null && String(pos).trim() !== '') {
        argv.push(String(pos));
      }
    }
  }

  return argv;
}
