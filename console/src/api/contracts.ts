export const serverResourceStates = [
  "ready",
  "empty",
  "unavailable",
  "stale",
  "degraded",
  "error",
] as const;

export type ServerResourceState = (typeof serverResourceStates)[number];
export type ClientResourceState = ServerResourceState | "loading";

export interface ResourceEnvelope<T = unknown> {
  state: ServerResourceState;
  data: T | null;
  reason_code?: string;
  detail?: string;
  as_of?: string;
  cursor?: number;
}

export interface LoadingResource {
  state: "loading";
  data: null;
}

export type ResourceResult<T = unknown> = ResourceEnvelope<T> | LoadingResource;

export interface CommandAcknowledgement {
  acknowledgement_id?: string;
  status: "accepted" | "completed" | "unavailable" | "conflict";
  resource_id?: string;
  reason_code?: string;
}

export interface Principal {
  user_id: string;
  session_id: string;
  organization_id: string;
  organization_role: string | null;
  organization_permissions: string[];
}

export type JsonRecord = Record<string, unknown>;

const states = new Set<string>(serverResourceStates);

export function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function decodeResourceEnvelope<T = unknown>(value: unknown): ResourceEnvelope<T> {
  if (!isJsonRecord(value) || typeof value.state !== "string" || !states.has(value.state)) {
    throw new Error("Invalid resource envelope");
  }
  if (!("data" in value)) {
    throw new Error("Invalid resource envelope");
  }
  for (const key of ["reason_code", "detail", "as_of"] as const) {
    if (value[key] !== undefined && typeof value[key] !== "string") {
      throw new Error("Invalid resource envelope");
    }
  }
  if (
    value.cursor !== undefined &&
    (typeof value.cursor !== "number" || !Number.isSafeInteger(value.cursor) || value.cursor < 0)
  ) {
    throw new Error("Invalid resource envelope");
  }
  return value as unknown as ResourceEnvelope<T>;
}

export function decodeCommandAcknowledgement(value: unknown): CommandAcknowledgement {
  const validStatuses = new Set(["accepted", "completed", "unavailable", "conflict"]);
  const allowedKeys = new Set([
    "status",
    "acknowledgement_id",
    "resource_id",
    "reason_code",
  ]);
  if (
    !isJsonRecord(value) ||
    typeof value.status !== "string" ||
    !validStatuses.has(value.status) ||
    Object.keys(value).some((key) => !allowedKeys.has(key)) ||
    (value.acknowledgement_id !== undefined && typeof value.acknowledgement_id !== "string") ||
    (value.resource_id !== undefined && typeof value.resource_id !== "string") ||
    (value.reason_code !== undefined && typeof value.reason_code !== "string") ||
    !(
      (typeof value.acknowledgement_id === "string" && value.acknowledgement_id.length > 0) ||
      value.status === "unavailable" ||
      value.status === "conflict"
    )
  ) {
    throw new Error("Invalid command acknowledgement");
  }
  return value as unknown as CommandAcknowledgement;
}

export function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "Available in record detail";
}
