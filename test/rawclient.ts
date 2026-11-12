import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

type Json = Record<string, any>;

/**
 * A minimal MCP client of the 2025 era written against the wire protocol (newline-delimited
 * JSON-RPC over stdio), with no SDK: it tests what a real client of that era sees.
 */
export class RawClient {
  readonly child: ChildProcessWithoutNullStreams;
  stderr = "";
  stdoutNonJson: string[] = [];
  readonly serverRequests: Json[] = [];
  /** Answers requests the server sends (elicitation/create). */
  onServerRequest: (message: Json) => Json | Promise<Json> = () => ({ action: "cancel" });
  private buffer = "";
  private nextId = 1;
  private readonly pending = new Map<number, { resolve: (v: Json) => void; reject: (e: Error) => void }>();

  constructor(command: string, args: string[], env: Record<string, string>) {
    this.child = spawn(command, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    this.child.stderr.on("data", (d: Buffer) => { this.stderr += d.toString(); });
    this.child.stdout.on("data", (d: Buffer) => this.onData(d.toString()));
  }

  private onData(text: string): void {
    this.buffer += text;
    let index = this.buffer.indexOf("\n");
    while (index >= 0) {
      const line = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + 1);
      if (line !== "") this.onLine(line);
      index = this.buffer.indexOf("\n");
    }
  }

  private onLine(line: string): void {
    let message: Json;
    try {
      message = JSON.parse(line) as Json;
    } catch {
      this.stdoutNonJson.push(line);
      return;
    }
    if (message["method"] !== undefined && message["id"] !== undefined) {
      this.serverRequests.push(message);
      void Promise.resolve(this.onServerRequest(message)).then((result) => {
        this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: message["id"], result })}\n`);
      });
      return;
    }
    if (message["id"] !== undefined) {
      const waiter = this.pending.get(message["id"] as number);
      if (waiter !== undefined) {
        this.pending.delete(message["id"] as number);
        waiter.resolve(message);
      }
    }
  }

  request(method: string, params: Json = {}, timeoutMs = 20_000): Promise<Json> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for ${method}; stderr: ${this.stderr.slice(0, 500)}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject,
      });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  notify(method: string, params: Json = {}): void {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  }

  async initialize(capabilities: Json): Promise<Json> {
    const response = await this.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities,
      clientInfo: { name: "raw-test-client", version: "0.0.0" },
    });
    this.notify("notifications/initialized");
    return response;
  }

  async callTool(name: string, args: Json): Promise<Json> {
    const response = await this.request("tools/call", { name, arguments: args }, 30_000);
    if (response["error"] !== undefined) throw new Error(`protocol error: ${JSON.stringify(response["error"])}`);
    const result = response["result"] as Json;
    const text = (result["content"]?.[0]?.text as string | undefined) ?? "{}";
    return { isError: result["isError"] === true, body: JSON.parse(text) as Json, raw: result };
  }

  async close(): Promise<void> {
    this.child.stdin.end();
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => { this.child.kill("SIGKILL"); resolve(); }, 3000);
      this.child.on("exit", () => { clearTimeout(timer); resolve(); });
    });
  }
}
