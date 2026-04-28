/**
 * @auth-service/embedded-auth — parent-window helpers for `/embedded-login` (protocol v2).
 * See `docs/EMBEDDED_IFRAME_PROTOCOL.md` in the Auth Service repo.
 */

export type IframeMessageV1 = {
  v: 1;
  type: string;
  ts: number;
  source: "auth_iframe" | "parent_sdk";
  nonce: string;
  [k: string]: unknown;
};

export type EmbeddedAuthOptions = {
  /** Issuer base URL, e.g. `https://auth.example.com` (no trailing slash). */
  issuer: string;
  /** Public OAuth `client_id`. */
  clientId: string;
  /**
   * Origins allowed for `message` events. Must include the auth issuer origin
   * and match `embedded_parent_origins` in the admin UI (plus your app origin for INIT).
   */
  allowedMessageOrigins: string[];
  /** Called for successful v2 or legacy `AUTH_SUCCESS`. `refresh_token` may be absent in the iframe (server strips it). */
  onSuccess?: (tokens: { access_token: string; refresh_token?: string }) => void;
  onError?: (err: { error: string; message: string; raw: unknown }) => void;
  onReady?: (ev: IframeMessageV1) => void;
  onSessionEnded?: (ev: IframeMessageV1) => void;
};

function joinUrl(issuer: string, path: string): string {
  return `${issuer.replace(/\/$/, "")}${path.startsWith("/") ? path : `/${path}`}`;
}

/**
 * Create an iframe and optional protocol-v2 message bridge.
 * Does not set iframe `src` until you call `load()`.
 */
export function createEmbeddedAuth(options: EmbeddedAuthOptions) {
  const iframe = document.createElement("iframe");
  iframe.setAttribute("title", "Sign in");
  iframe.style.width = "100%";
  iframe.style.minHeight = "420px";
  iframe.style.border = "0";
  const allowed = new Set(options.allowedMessageOrigins);

  const onMessage = (ev: MessageEvent) => {
    if (ev.source !== iframe.contentWindow) return;
    if (!ev.origin || !allowed.has(ev.origin)) return;
    const raw = ev.data;
    if (raw == null) return;
    let data: unknown;
    try {
      data = typeof raw === "string" ? JSON.parse(raw) : raw;
    } catch {
      return;
    }
    if (typeof data !== "object" || data === null) return;

    const o = data as Record<string, unknown>;
    if (o.v === 1) {
      const msg = data as IframeMessageV1;
      if (msg.type === "EMBED_READY" && options.onReady) options.onReady(msg);
      if (msg.type === "SESSION_ENDED" && options.onSessionEnded) options.onSessionEnded(msg);
      if (msg.type === "AUTH_SUCCESS" && typeof o.access_token === "string") {
        options.onSuccess?.({
          access_token: o.access_token,
          refresh_token: typeof o.refresh_token === "string" ? o.refresh_token : undefined,
        });
        return;
      }
      if (msg.type === "AUTH_ERROR") {
        options.onError?.({
          error: String(o.error ?? "AUTH_ERROR"),
          message: String(o.message ?? ""),
          raw: data,
        });
      }
    } else {
      if (o.type === "AUTH_SUCCESS" && typeof o.access_token === "string") {
        options.onSuccess?.({
          access_token: o.access_token,
          refresh_token: typeof o.refresh_token === "string" ? o.refresh_token : undefined,
        });
        return;
      }
      if (o.type === "AUTH_ERROR") {
        options.onError?.({
          error: String(o.error ?? "AUTH_ERROR"),
          message: String(o.message ?? ""),
          raw: data,
        });
      }
    }
  };

  const load = () => {
    const src = new URL(joinUrl(options.issuer, "/embedded-login"));
    src.searchParams.set("client_id", options.clientId);
    iframe.src = src.toString();
  };

  const destroy = () => {
    window.removeEventListener("message", onMessage);
    iframe.remove();
  };

  const sendToIframe = (part: { type: string; v?: 1; source?: "parent_sdk"; [k: string]: unknown }) => {
    const w = iframe.contentWindow;
    if (!w) return;
    const target = iframe.src && iframe.src !== "about:blank" ? new URL(iframe.src).origin : new URL(options.issuer).origin;
    const payload: Record<string, unknown> = {
      ...part,
      v: 1,
      ts: Math.floor(Date.now() / 1000),
      source: "parent_sdk",
      nonce: typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `${Math.random()}`,
    };
    w.postMessage(payload, target);
  };

  window.addEventListener("message", onMessage);

  return {
    iframe,
    load,
    destroy,
    /** Send `INIT` to iframe (v2; iframe must have `embedded_protocol_v2` enabled on the client). */
    initHandshake: () => sendToIframe({ type: "INIT" }),
    /** Send approved theme patch (v2); see protocol doc for `theme` shape. */
    updateTheme: (theme: object) => sendToIframe({ type: "THEME_UPDATE", theme }),
    /** Ask iframe to clear local UI; revoke tokens via `POST /auth/logout` with refresh. */
    logout: () => sendToIframe({ type: "LOGOUT" }),
  };
}

/**
 * Type guard: message looks like a v1 envelope.
 */
export function isEnvelopeV1(x: unknown): x is IframeMessageV1 {
  if (typeof x !== "object" || x === null) return false;
  const o = x as Record<string, unknown>;
  return o.v === 1 && typeof o.type === "string" && typeof o.nonce === "string";
}
