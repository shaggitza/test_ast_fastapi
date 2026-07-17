import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { lstat, realpath } from "node:fs/promises";
import { connect } from "node:net";
import { isAbsolute, parse, resolve } from "node:path";
import { ReviewDraftSchema } from "./review-schema.ts";

const MAX_REQUEST_BYTES = 2_200_000;
const MAX_RESPONSE_BYTES = 16 * 1024;
const DEADLINE_MS = 600_000;
const CAPABILITY = /^[0-9a-f]{64}$/;

interface Receipt {
  schema_version: 1;
  attempt_id: string;
  lane: "A" | "B";
  repository: string;
  pr: number;
  recommendation: "positive" | "negative_control" | "unknown" | "not_evaluable";
  changed_symbols: number;
  claims: number;
  unknowns: number;
  bytes: number;
  sha256: string;
  summary: string;
}

interface BrokerResponse {
  protocol_version: 3;
  ok: boolean;
  code: string;
  diagnostic?: string;
  summary?: string;
  receipt?: Receipt;
}

async function rejectSymlinkAncestors(target: string): Promise<void> {
  const root = parse(target).root;
  let current = root;
  for (const part of target.slice(root.length).split("/").filter(Boolean).slice(0, -1)) {
    current = resolve(current, part);
    let status;
    try {
      status = await lstat(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    if (status.isSymbolicLink()) throw new Error("submission socket has a symlink ancestor");
  }
}

async function trustedSocketPath(): Promise<string> {
  const socketPath = process.env.PILOT_REVIEW_SUBMIT_SOCKET;
  if (!socketPath || !isAbsolute(socketPath) || resolve(socketPath) !== socketPath) {
    throw new Error("submission socket is not a normalized absolute path");
  }
  await rejectSymlinkAncestors(socketPath);
  const status = await lstat(socketPath);
  const uid = process.getuid?.();
  if (!status.isSocket() || uid === undefined || status.uid !== uid || (status.mode & 0o777) !== 0o600) {
    throw new Error("submission socket owner, type, or mode is invalid");
  }
  return socketPath;
}

function trustedCapability(): string {
  const capability = process.env.PILOT_REVIEW_SUBMIT_CAPABILITY;
  if (!capability || !CAPABILITY.test(capability)) {
    throw new Error("submission capability is unavailable");
  }
  return capability;
}

function parseResponse(raw: Buffer): BrokerResponse {
  if (raw.length === 0 || raw.length > MAX_RESPONSE_BYTES) throw new Error("invalid broker response size");
  let value: unknown;
  try {
    value = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error("broker response is not strict JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("broker response is not an object");
  }
  const response = value as Record<string, unknown>;
  if (
    response.protocol_version !== 3 ||
    typeof response.ok !== "boolean" ||
    typeof response.code !== "string"
  ) {
    throw new Error("broker response fields are invalid");
  }
  const keys = Object.keys(response).sort().join(",");
  const allowed = response.ok
    ? "code,ok,protocol_version,receipt,summary"
    : response.diagnostic === undefined
      ? "code,ok,protocol_version"
      : "code,diagnostic,ok,protocol_version";
  if (keys !== allowed) throw new Error("broker response keys are invalid");
  if (response.ok) {
    const receipt = response.receipt;
    if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
      throw new Error("broker receipt is invalid");
    }
    const receiptRecord = receipt as Record<string, unknown>;
    const receiptKeys = Object.keys(receiptRecord).sort().join(",");
    if (
      receiptKeys !==
        "attempt_id,bytes,changed_symbols,claims,lane,pr,recommendation,repository,schema_version,sha256,summary,unknowns" ||
      receiptRecord.schema_version !== 1 ||
      typeof receiptRecord.summary !== "string" ||
      typeof receiptRecord.sha256 !== "string" ||
      !/^sha256:[0-9a-f]{64}$/.test(receiptRecord.sha256)
    ) {
      throw new Error("broker receipt fields are invalid");
    }
  } else if (
    response.diagnostic !== undefined &&
    (typeof response.diagnostic !== "string" || response.diagnostic.length > 500)
  ) {
    throw new Error("broker diagnostic is invalid");
  }
  return response as unknown as BrokerResponse;
}

async function brokerRequest(
  socketPath: string,
  request: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<BrokerResponse> {
  if (signal?.aborted) throw new Error("submission cancelled");
  const payload = Buffer.from(`${JSON.stringify(request)}\n`, "utf8");
  if (payload.length === 0 || payload.length > MAX_REQUEST_BYTES) {
    throw new Error("submission request exceeds byte limit");
  }
  const frame = Buffer.allocUnsafe(payload.length + 4);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);

  return new Promise<BrokerResponse>((resolvePromise, rejectPromise) => {
    const client = connect(socketPath);
    let expected: number | undefined;
    let buffered = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => finish(new Error("submission broker deadline exceeded")), DEADLINE_MS);

    const finish = (error?: Error, response?: BrokerResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", aborted);
      client.destroy();
      if (error) rejectPromise(error);
      else resolvePromise(response!);
    };
    const aborted = () => finish(new Error("submission cancelled"));
    signal?.addEventListener("abort", aborted, { once: true });

    client.once("connect", () => client.write(frame));
    client.on("data", (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (expected === undefined && buffered.length >= 4) {
        expected = buffered.readUInt32BE(0);
        buffered = buffered.subarray(4);
        if (expected <= 0 || expected > MAX_RESPONSE_BYTES) {
          finish(new Error("invalid broker response frame"));
          return;
        }
      }
      if (expected !== undefined && buffered.length >= expected) {
        if (buffered.length !== expected) {
          finish(new Error("broker response contains trailing bytes"));
          return;
        }
        try {
          finish(undefined, parseResponse(buffered));
        } catch (error) {
          finish(error as Error);
        }
      }
    });
    client.once("error", (error) => finish(error));
    client.once("end", () => {
      if (!settled) finish(new Error("truncated broker response"));
    });
  });
}

const submitBlindReview = defineTool({
  name: "submit_blind_review",
  label: "Submit Blind Review",
  description:
    "Validate and submit the final semantic blind-review draft to supervisor-owned escrow. " +
    "The broker injects identity, policy hashes, commits, blob OIDs, IDs, evidence ordinals and timestamps. " +
    "No destination or transport path is model-selectable. If rejected, correct only the reported semantic fields.",
  promptSnippet: "Validate and submit the final typed blind-review artifact",
  promptGuidelines: [
    "Use submit_blind_review as the final action for a blind review; never emit artifact JSON as prose.",
    "After submit_blind_review succeeds, do not emit another assistant response.",
  ],
  parameters: ReviewDraftSchema,
  async execute(_toolCallId, params, signal, _onUpdate, ctx) {
    const socketPath = await trustedSocketPath();
    const capability = trustedCapability();
    const cwd = await realpath(ctx.cwd);
    const response = await brokerRequest(
      socketPath,
      { protocol_version: 3, capability, cwd, draft: params },
      signal,
    );
    if (!response.ok) {
      const diagnostic = typeof response.diagnostic === "string" ? ` diagnostic=${response.diagnostic}` : "";
      throw new Error(`SUBMISSION_REJECTED code=${response.code}${diagnostic}`);
    }
    if (
      response.code !== "SUBMITTED" ||
      typeof response.summary !== "string" ||
      !response.receipt ||
      response.receipt.summary !== response.summary
    ) {
      throw new Error("broker success response is invalid");
    }
    return {
      content: [{ type: "text" as const, text: response.summary }],
      details: response.receipt,
      terminate: true,
    };
  },
});

export default function (pi: ExtensionAPI) {
  pi.registerTool(submitBlindReview);
}
