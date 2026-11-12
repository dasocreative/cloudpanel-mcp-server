import type { ToolClass } from "./classes.ts";

export interface ApprovalRequest {
  /** Names the request on the wire; derived from tool, profile and arguments. */
  readonly key: string;
  readonly kind: "confirm-box" | "type-target";
  /** What the human must type, for "type-target". */
  readonly target?: string;
  readonly message: string;
  readonly requestedSchema: {
    readonly type: "object";
    readonly properties: Record<string, Record<string, unknown>>;
    readonly required: readonly string[];
  };
}

export type HumanDecision =
  | { readonly action: "accept"; readonly content?: Readonly<Record<string, unknown>> | undefined }
  | { readonly action: "decline" | "cancel" | "timeout" | "error"; readonly detail?: string };

export type Verdict =
  | { readonly approved: true }
  | { readonly approved: false; readonly decision: string; readonly reason: string };

export interface ApprovalInput {
  readonly key: string;
  readonly cls: Exclude<ToolClass, "read">;
  readonly profile: string;
  readonly summary: string;
  /** The exact command, passwords redacted. */
  readonly command: string;
  readonly effects: readonly string[];
  readonly reversible: string;
  /** Required for destructive and admin classes: the name the human must type. */
  readonly target?: string | undefined;
  readonly noun?: string | undefined;
}

function printable(text: string): string {
  return text.replace(/[^\x20-\x7e\n]/g, "?");
}

/** The question the human sees. Built here from validated state; the model contributes only validated values. */
export function buildApprovalRequest(input: ApprovalInput): ApprovalRequest {
  const needsTyping = input.cls !== "write";
  if (needsTyping && (input.target === undefined || input.target === "")) {
    throw new Error("a destructive or admin approval needs a target to type");
  }
  const lines = [
    `cloudpanel-mcp-server | profile "${input.profile}" | ${input.cls.toUpperCase()}`,
    input.summary,
    "",
    `Command run on the server: ${input.command}`,
    ...(input.effects.length > 0 ? ["Effects:", ...input.effects.map((e) => `  - ${e}`)] : []),
    `Undo: ${input.reversible}`,
    "",
    needsTyping
      ? `To approve, type the ${input.noun ?? "target"} name exactly: ${input.target}`
      : "To approve, tick the box. Decline or cancel to refuse.",
  ];
  const message = printable(lines.join("\n"));
  if (needsTyping) {
    return {
      key: input.key,
      kind: "type-target",
      target: input.target as string,
      message,
      requestedSchema: {
        type: "object",
        properties: {
          typed: {
            type: "string",
            title: `Type the ${input.noun ?? "target"} name to confirm`,
            minLength: 1,
            maxLength: 253,
          },
        },
        required: ["typed"],
      },
    };
  }
  return {
    key: input.key,
    kind: "confirm-box",
    message,
    requestedSchema: {
      type: "object",
      properties: {
        approve: { type: "boolean", title: "Yes, run this command", default: false },
      },
      required: ["approve"],
    },
  };
}

/** Anything but an explicit accept with the right content refuses. */
export function evaluateDecision(request: ApprovalRequest, decision: HumanDecision): Verdict {
  if (decision.action !== "accept") {
    return {
      approved: false,
      decision: decision.action,
      reason: `the human did not approve (${decision.action})`,
    };
  }
  const content = decision.content;
  if (content === undefined || content === null || typeof content !== "object") {
    return { approved: false, decision: "mismatch", reason: "the approval carried no content" };
  }
  if (request.kind === "confirm-box") {
    return content["approve"] === true
      ? { approved: true }
      : { approved: false, decision: "mismatch", reason: "the box was not ticked" };
  }
  return typeof content["typed"] === "string" && content["typed"] === request.target
    ? { approved: true }
    : { approved: false, decision: "mismatch", reason: "the typed name does not match the target" };
}

/** The elicitation capability needed to ask a form question. A bare `{}` means form only. */
export function canElicitForm(capability: unknown): boolean {
  if (capability === null || typeof capability !== "object") return false;
  const cap = capability as { form?: unknown; url?: unknown };
  if (cap.form !== undefined) return true;
  return cap.url === undefined; // `{}`: form mode only
}
