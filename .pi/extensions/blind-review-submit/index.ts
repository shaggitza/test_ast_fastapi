import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { createHash } from "node:crypto";
import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { connect } from "node:net";
import { isAbsolute, join, parse, resolve } from "node:path";
import { ReviewDraftSchema } from "./review-schema.ts";

const MAX_REQUEST_BYTES = 2_200_000;
const MAX_RESPONSE_BYTES = 16 * 1024;
const DEADLINE_MS = 1_800_000;
const CAPABILITY = /^[0-9a-f]{64}$/;
const CORRECTABLE_REJECTION_CODES = new Set(["DRAFT_INVALID", "EVIDENCE_INVALID"]);

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

interface BrokerSuccessResponse {
  protocol_version: 3;
  ok: true;
  code: string;
  summary: string;
  receipt: Receipt;
}

interface BrokerRejectionResponse {
  protocol_version: 3;
  ok: false;
  code: string;
  diagnostic?: string;
}

type BrokerResponse = BrokerSuccessResponse | BrokerRejectionResponse;

interface RejectionDetails {
  protocol_version: 3;
  ok: false;
  code: string;
  diagnostic?: string;
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

interface TransportBinding {
  socketPath: string;
  capability: string;
  cwd: string;
}

async function validatePrivateDirectory(path: string, uid: number): Promise<void> {
  await rejectSymlinkAncestors(join(path, "entry"));
  const status = await lstat(path);
  if (!status.isDirectory() || status.isSymbolicLink() || status.uid !== uid || (status.mode & 0o777) !== 0o700) {
    throw new Error("submission registry directory is invalid");
  }
}

async function registryTransport(cwd: string, uid: number): Promise<TransportBinding> {
  const cwdStatus = await stat(cwd, { bigint: true });
  if (!cwdStatus.isDirectory() || cwdStatus.uid !== BigInt(uid)) {
    throw new Error("submission cwd identity is invalid");
  }
  const runtimeRoot = `/tmp/pilot-review-v3-${uid}`;
  const registry = join(runtimeRoot, "registry");
  await validatePrivateDirectory(runtimeRoot, uid);
  await validatePrivateDirectory(registry, uid);
  const key = createHash("sha256")
    .update(`${cwdStatus.dev.toString()}:${cwdStatus.ino.toString()}`, "utf8")
    .digest("hex");
  const descriptorPath = join(registry, `${key}.json`);
  const descriptorStatus = await lstat(descriptorPath);
  if (
    !descriptorStatus.isFile() ||
    descriptorStatus.isSymbolicLink() ||
    descriptorStatus.uid !== uid ||
    (descriptorStatus.mode & 0o777) !== 0o600
  ) {
    throw new Error("submission registry descriptor is invalid");
  }
  let value: unknown;
  try {
    value = JSON.parse(await readFile(descriptorPath, "utf8"));
  } catch {
    throw new Error("submission registry descriptor is not JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("submission registry descriptor is not an object");
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !==
      "attempt_id,capability,cwd,cwd_device,cwd_inode,protocol,schema_version,socket_path" ||
    record.schema_version !== 1 ||
    record.protocol !== "blind-review-native-registry-v3" ||
    typeof record.attempt_id !== "string" ||
    record.cwd !== cwd ||
    record.cwd_device !== cwdStatus.dev.toString() ||
    record.cwd_inode !== cwdStatus.ino.toString() ||
    typeof record.socket_path !== "string" ||
    typeof record.capability !== "string" ||
    !CAPABILITY.test(record.capability)
  ) {
    throw new Error("submission registry descriptor fields are invalid");
  }
  return { socketPath: record.socket_path, capability: record.capability, cwd };
}

async function trustedTransport(inputCwd: string): Promise<TransportBinding> {
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("submission peer uid is unavailable");
  const cwd = await realpath(inputCwd);
  const socketPath = process.env.PILOT_REVIEW_SUBMIT_SOCKET;
  const capability = process.env.PILOT_REVIEW_SUBMIT_CAPABILITY;
  if ((socketPath === undefined) !== (capability === undefined)) {
    throw new Error("submission environment binding is incomplete");
  }
  const binding =
    socketPath !== undefined && capability !== undefined
      ? { socketPath, capability, cwd }
      : await registryTransport(cwd, uid);
  if (!CAPABILITY.test(binding.capability)) throw new Error("submission capability is unavailable");
  if (!isAbsolute(binding.socketPath) || resolve(binding.socketPath) !== binding.socketPath) {
    throw new Error("submission socket is not a normalized absolute path");
  }
  await rejectSymlinkAncestors(binding.socketPath);
  const socketStatus = await lstat(binding.socketPath);
  if (!socketStatus.isSocket() || socketStatus.uid !== uid || (socketStatus.mode & 0o777) !== 0o600) {
    throw new Error("submission socket owner, type, or mode is invalid");
  }
  return binding;
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
    typeof response.code !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,99}$/.test(response.code)
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

function compactDiagnostic(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function submissionToolResult(response: BrokerResponse) {
  if (!response.ok) {
    const diagnostic = response.diagnostic === undefined
      ? ""
      : ` diagnostic=${compactDiagnostic(response.diagnostic)}`;
    if (!CORRECTABLE_REJECTION_CODES.has(response.code)) {
      throw new Error(`SUBMISSION_FATAL code=${response.code}${diagnostic}`);
    }
    const details: RejectionDetails = {
      protocol_version: 3,
      ok: false,
      code: response.code,
      ...(response.diagnostic === undefined ? {} : { diagnostic: response.diagnostic }),
    };
    return {
      content: [{ type: "text" as const, text: `SUBMISSION_REJECTED code=${response.code}${diagnostic}` }],
      details,
      terminate: false,
    };
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
    const binding = await trustedTransport(ctx.cwd);
    const response = await brokerRequest(
      binding.socketPath,
      { protocol_version: 3, capability: binding.capability, cwd: binding.cwd, draft: params },
      signal,
    );
    return submissionToolResult(response);
  },
});

export default function (pi: ExtensionAPI) {
  pi.registerTool(submitBlindReview);
}
