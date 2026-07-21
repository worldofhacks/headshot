import {
  decodeCommandAcknowledgement,
  decodeResourceEnvelope,
  type CommandAcknowledgement,
  type ResourceEnvelope,
} from "./contracts";

type GetSessionCredential = () => Promise<string | null>;

interface ApiClientOptions {
  origin?: string;
  getToken: GetSessionCredential;
  fetchImpl?: typeof fetch;
  createIdempotencyKey?: () => string;
}

export interface ApiClient {
  read<T = unknown>(path: string, signal?: AbortSignal): Promise<ResourceEnvelope<T>>;
  command<T extends object = Record<string, never>>(
    path: string,
    payload: T,
    signal?: AbortSignal,
    idempotencyKey?: string,
  ): Promise<CommandAcknowledgement>;
}

export class ApiClientError extends Error {
  readonly code: string;
  readonly status: number | null;

  constructor(message: string, code: string, status: number | null = null) {
    super(message);
    this.name = "ApiClientError";
    this.code = code;
    this.status = status;
  }
}

function normalizeOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ApiClientError("Invalid application origin", "invalid_origin");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "/" && url.pathname !== "")
  ) {
    throw new ApiClientError("Invalid application origin", "invalid_origin");
  }
  return url.origin;
}

function apiUrl(origin: string, path: string): string {
  const normalized = path.startsWith("/") ? path.slice(1) : path;
  if (
    normalized.length === 0 ||
    normalized.startsWith("/") ||
    normalized.includes("\\") ||
    normalized.includes("?") ||
    normalized.includes("#") ||
    normalized.split("/").some((part) => part === "" || part === "." || part === "..") ||
    /[\u0000-\u001f\u007f]/.test(normalized) ||
    /^[a-z][a-z\d+.-]*:/i.test(normalized)
  ) {
    throw new ApiClientError("Invalid API path", "invalid_path");
  }
  return `${origin}/api/v1/${normalized}`;
}

function genericFailure(status: number): ApiClientError {
  if (status === 401) return new ApiClientError("Authentication required", "unauthenticated", 401);
  if (status === 403) return new ApiClientError("Access denied", "forbidden", 403);
  if (status === 503) return new ApiClientError("Service unavailable", "unavailable", 503);
  return new ApiClientError("Request failed", "request_failed", status);
}

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.clone().json();
  } catch {
    throw new ApiClientError("Invalid server response", "invalid_response", response.status);
  }
}

export function createApiClient(options: ApiClientOptions): ApiClient {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const defaultOrigin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
  const origin = normalizeOrigin(options.origin ?? defaultOrigin);
  const createIdempotencyKey = options.createIdempotencyKey ?? (() => globalThis.crypto.randomUUID());

  async function sessionCredential(): Promise<string> {
    let value: string | null;
    try {
      value = await options.getToken();
    } catch {
      throw new ApiClientError("Authentication unavailable", "authentication_unavailable");
    }
    if (!value) throw new ApiClientError("Authentication required", "unauthenticated", 401);
    return value;
  }

  async function request(
    path: string,
    init: RequestInit,
    acceptedErrorStatuses: readonly number[] = [],
  ): Promise<Response> {
    const url = apiUrl(origin, path);
    const credential = await sessionCredential();
    const headers: Record<string, string> = {
      ...((init.headers ?? {}) as Record<string, string>),
      Accept: "application/json",
      Authorization: `Bearer ${credential}`,
    };
    try {
      const response = await fetchImpl(url, {
        ...init,
        headers,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      });
      if (!response.ok && !acceptedErrorStatuses.includes(response.status)) {
        throw genericFailure(response.status);
      }
      return response;
    } catch (error) {
      if (error instanceof ApiClientError) throw error;
      throw new ApiClientError("Request failed", "network_failure");
    }
  }

  return {
    async read<T>(path: string, signal?: AbortSignal): Promise<ResourceEnvelope<T>> {
      const response = await request(path, { method: "GET", signal });
      try {
        return decodeResourceEnvelope<T>(await responseJson(response));
      } catch (error) {
        if (error instanceof ApiClientError) throw error;
        throw new ApiClientError("Invalid server response", "invalid_response", response.status);
      }
    },

    async command<T extends object>(
      path: string,
      payload: T,
      signal?: AbortSignal,
      idempotencyKey?: string,
    ): Promise<CommandAcknowledgement> {
      const response = await request(
        path,
        {
          method: "POST",
          signal,
          body: JSON.stringify(payload),
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": idempotencyKey ?? createIdempotencyKey(),
          },
        },
        [409, 503],
      );
      try {
        return decodeCommandAcknowledgement(await responseJson(response));
      } catch (error) {
        if (error instanceof ApiClientError) throw error;
        throw new ApiClientError("Invalid server response", "invalid_response", response.status);
      }
    },
  };
}
