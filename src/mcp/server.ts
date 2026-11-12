import { Server, inputRequired, inputResponse } from "@modelcontextprotocol/server";
import { NeedInput, type ClientIO, type Engine } from "../engine.ts";
import { canElicitForm, type ApprovalRequest, type HumanDecision } from "../policy/approval.ts";

/**
 * The only module that talks to the MCP SDK. It lists the engine's tools, hands every call to the
 * engine and turns the engine's approval step into the right protocol exchange for the connected
 * client's era (docs/adr/0001, docs/adr/0002).
 */

/** A person is on the other end: far longer than the SDK's 60-second default. */
export const HUMAN_TIMEOUT_MS = 10 * 60_000;

const MODERN_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities";

type Era = "legacy" | "modern";

interface CallContext {
  readonly mcpReq: {
    readonly signal: AbortSignal;
    readonly envelope?: Record<string, unknown> | undefined;
    readonly inputResponses?: Record<string, unknown> | undefined;
    readonly elicitInput: (
      params: { mode: "form"; message: string; requestedSchema: never },
      options?: { timeout?: number; signal?: AbortSignal },
    ) => Promise<{ action: "accept" | "decline" | "cancel"; content?: Record<string, unknown> }>;
  };
}

function describeError(error: unknown): HumanDecision {
  const message = error instanceof Error ? error.message : String(error);
  const code = (error as { code?: unknown } | null)?.code;
  if (/timed? ?out/i.test(message) || code === "REQUEST_TIMEOUT" || code === -32001) {
    return { action: "timeout", detail: "no answer before the timeout" };
  }
  return { action: "error", detail: message.slice(0, 120) };
}

export function makeClientIO(era: Era, server: Server, ctx: CallContext): ClientIO {
  const capability =
    era === "modern"
      ? (ctx.mcpReq.envelope?.[MODERN_CAPABILITIES_KEY] as { elicitation?: unknown } | undefined)?.elicitation
      : (server.getClientCapabilities() as { elicitation?: unknown } | undefined)?.elicitation;
  const canForm = canElicitForm(capability);
  /** The answer the client sent for this question in the 2026 era, or undefined. */
  const answerFor = (key: string): HumanDecision | undefined => {
    const view = inputResponse(ctx.mcpReq.inputResponses, key);
    if (view.kind === "missing") return undefined;
    if (view.kind === "elicit") {
      return view.action === "accept"
        ? { action: "accept", content: view.content as Record<string, unknown> | undefined }
        : { action: view.action };
    }
    return { action: "error", detail: "unexpected kind of answer" };
  };
  return {
    canElicitForm: canForm,
    replaysAnswers: era === "modern",
    ...(era === "modern" ? { answerFor } : {}),
    async ask(request: ApprovalRequest): Promise<HumanDecision> {
      if (era === "legacy") {
        try {
          const answer = await ctx.mcpReq.elicitInput(
            { mode: "form", message: request.message, requestedSchema: request.requestedSchema as never },
            { timeout: HUMAN_TIMEOUT_MS, signal: ctx.mcpReq.signal },
          );
          return answer.action === "accept"
            ? { action: "accept", content: answer.content }
            : { action: answer.action };
        } catch (error) {
          return describeError(error);
        }
      }
      const answer = answerFor(request.key);
      if (answer === undefined) throw new NeedInput(request);
      return answer;
    },
  };
}

export function createServerFactory(engine: Engine, version: string) {
  return ({ era }: { era: Era }): Server => {
    const server = new Server(
      { name: "cloudpanel-mcp-server", version },
      { capabilities: { tools: {} }, instructions: engine.instructions() },
    );
    server.setRequestHandler("tools/list", async () => ({
      tools: engine.descriptors() as never,
    }));
    server.setRequestHandler("tools/call", async (request, ctx) => {
      const io = makeClientIO(era, server, ctx as unknown as CallContext);
      try {
        const outcome = await engine.call(request.params.name, request.params.arguments, io);
        return {
          isError: outcome.isError,
          content: [{ type: "text" as const, text: JSON.stringify(outcome.body, null, 2) }],
        };
      } catch (error) {
        if (error instanceof NeedInput) {
          return inputRequired({
            inputRequests: {
              [error.request.key]: inputRequired.elicit({
                message: error.request.message,
                requestedSchema: error.request.requestedSchema as never,
              }),
            },
          }) as never;
        }
        throw error;
      }
    });
    return server;
  };
}
