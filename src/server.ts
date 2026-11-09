import { execFile } from 'node:child_process';
import readline from 'node:readline';
import { promisify } from 'node:util';
import {
  auditCommandExecution,
  createSanitizedEnv
} from './firewall.js';
import {
  buildArgvFromToolInput,
  compileToMcpTools,
  parseCliHelp
} from './parser.js';
import { truncateCliOutput } from './truncator.js';
import {
  FirewallPolicy,
  McpToolDefinition,
  ParsedCliSpec,
  TruncatorOptions
} from './types.js';

const execFileAsync = promisify(execFile);

export interface McpServerConfig {
  specs: ParsedCliSpec[];
  firewallPolicy?: Partial<FirewallPolicy>;
  truncatorOptions?: TruncatorOptions;
  timeoutMs?: number;
}

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

/**
 * Introspects a live local binary by invoking `<binary> --help` safely without a shell.
 */
export async function introspectLocalBinary(binaryName: string): Promise<ParsedCliSpec> {
  try {
    const { stdout, stderr } = await execFileAsync(binaryName, ['--help'], {
      timeout: 5000,
      env: createSanitizedEnv()
    });
    const combined = (stdout || stderr || '').trim();
    return parseCliHelp(binaryName, combined);
  } catch (err: unknown) {
    // Many CLI tools exit with code 1 or 2 on --help but still print help text to stdout/stderr
    const execErr = err as { stdout?: string; stderr?: string; message?: string };
    const fallbackOutput = (execErr.stdout || execErr.stderr || '').trim();
    if (fallbackOutput.length > 20) {
      return parseCliHelp(binaryName, fallbackOutput);
    }
    throw new Error(
      `Failed to introspect binary '${binaryName}': ${execErr.message || String(err)}`
    );
  }
}

/**
 * Stateless MCP JSON-RPC 2.0 handler class that can be tested in-memory or attached to stdio.
 */
export class McpForgeServer {
  private readonly specMap = new Map<string, ParsedCliSpec>();
  private readonly tools: McpToolDefinition[] = [];
  private readonly firewallPolicy: Partial<FirewallPolicy>;
  private readonly truncatorOptions: TruncatorOptions;
  private readonly timeoutMs: number;

  constructor(config: McpServerConfig) {
    this.firewallPolicy = config.firewallPolicy ?? {};
    this.truncatorOptions = config.truncatorOptions ?? { maxTokens: 1500 };
    this.timeoutMs = config.timeoutMs ?? 15000;

    for (const spec of config.specs) {
      const compiled = compileToMcpTools(spec);
      for (const tool of compiled) {
        this.specMap.set(tool.name, spec);
        this.tools.push(tool);
      }
    }
  }

  public getTools(): McpToolDefinition[] {
    return this.tools;
  }

  public async handleRequest(req: JsonRpcRequest): Promise<JsonRpcResponse | null> {
    // Notifications (no id) do not return a response
    if (req.id === undefined) {
      return null;
    }

    try {
      switch (req.method) {
        case 'initialize':
          return {
            jsonrpc: '2.0',
            id: req.id,
            result: {
              protocolVersion: '2024-11-05',
              capabilities: {
                tools: { listChanged: false }
              },
              serverInfo: {
                name: 'mcp-forge',
                version: '1.0.0'
              }
            }
          };

        case 'ping':
          return {
            jsonrpc: '2.0',
            id: req.id,
            result: {}
          };

        case 'tools/list':
          return {
            jsonrpc: '2.0',
            id: req.id,
            result: {
              tools: this.tools
            }
          };

        case 'tools/call': {
          const params = (req.params || {}) as {
            name?: string;
            arguments?: Record<string, unknown>;
          };
          const toolName = params.name || '';
          const toolArgs = params.arguments || {};

          const spec = this.specMap.get(toolName);
          if (!spec) {
            return {
              jsonrpc: '2.0',
              id: req.id,
              error: {
                code: -32602,
                message: `Unknown MCP tool '${toolName}'. Available tools: ${ Array.from(
                  this.specMap.keys()
                ).join(', ')}`
              }
            };
          }

          const argv = buildArgvFromToolInput(spec, toolArgs);
          const audit = auditCommandExecution(spec.binaryName, argv, this.firewallPolicy);

          if (audit.status === 'block') {
            return {
              jsonrpc: '2.0',
              id: req.id,
              result: {
                isError: true,
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(
                      {
                        status: 'BLOCKED_BY_MCP_FORGE_FIREWALL',
                        commandPreview: audit.safeCommandPreview,
                        riskScore: audit.riskScore,
                        violations: audit.violations
                      },
                      null,
                      2
                    )
                  }
                ]
              }
            };
          }

          if (toolArgs.dry_run === true || audit.status === 'dry_run_required') {
            return {
              jsonrpc: '2.0',
              id: req.id,
              result: {
                isError: false,
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(
                      {
                        status: 'DRY_RUN_PREVIEW',
                        commandPreview: audit.safeCommandPreview,
                        binary: spec.binaryName,
                        argv,
                        riskScore: audit.riskScore,
                        violations: audit.violations
                      },
                      null,
                      2
                    )
                  }
                ]
              }
            };
          }

          // Execute safely via execFile (no shell interpolation)
          try {
            const { stdout, stderr } = await execFileAsync(spec.binaryName, argv, {
              timeout: this.timeoutMs,
              maxBuffer: 10 * 1024 * 1024,
              env: createSanitizedEnv()
            });
            const combinedOut = [stdout, stderr].filter(Boolean).join('\n');
            const truncated = truncateCliOutput(combinedOut, this.truncatorOptions);

            return {
              jsonrpc: '2.0',
              id: req.id,
              result: {
                isError: false,
                content: [
                  {
                    type: 'text',
                    text: truncated.content
                  }
                ],
                _meta: {
                  commandPreview: audit.safeCommandPreview,
                  originalLines: truncated.originalLines,
                  originalEstimatedTokens: truncated.originalEstimatedTokens,
                  finalEstimatedTokens: truncated.finalEstimatedTokens,
                  truncated: truncated.truncated,
                  redactedSecretsCount: truncated.redactedSecretsCount
                }
              }
            };
          } catch (execErr: unknown) {
            const errObj = execErr as {
              stdout?: string;
              stderr?: string;
              code?: number;
              message?: string;
            };
            const rawErrOut = [errObj.stdout, errObj.stderr, errObj.message]
              .filter(Boolean)
              .join('\n');
            const truncatedErr = truncateCliOutput(rawErrOut, this.truncatorOptions);

            return {
              jsonrpc: '2.0',
              id: req.id,
              result: {
                isError: true,
                content: [
                  {
                    type: 'text',
                    text: `Command failed (${audit.safeCommandPreview}):\n${truncatedErr.content}`
                  }
                ]
              }
            };
          }
        }

        default:
          return {
            jsonrpc: '2.0',
            id: req.id,
            error: {
              code: -32601,
              message: `Method not found: ${req.method}`
            }
          };
      }
    } catch (err: unknown) {
      return {
        jsonrpc: '2.0',
        id: req.id ?? null,
        error: {
          code: -32603,
          message: err instanceof Error ? err.message : String(err)
        }
      };
    }
  }

  /**
   * Starts listening for newline-delimited JSON-RPC 2.0 messages on stdin/stdout.
   */
  public startStdio(): void {
    const rl = readline.createInterface({
      input: process.stdin,
      terminal: false
    });

    rl.on('line', async (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const req = JSON.parse(trimmed) as JsonRpcRequest;
        const res = await this.handleRequest(req);
        if (res) {
          process.stdout.write(JSON.stringify(res) + '\n');
        }
      } catch {
        const parseErr: JsonRpcResponse = {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error: invalid JSON payload' }
        };
        process.stdout.write(JSON.stringify(parseErr) + '\n');
      }
    });
  }
}
