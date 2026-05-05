# @auth-service/embedded-auth

Browser helpers for embedding Auth Service `GET /embedded-login` in an iframe with **optional** postMessage **v2** (envelope, `EMBED_READY`, `INIT`, `THEME_UPDATE`).

- Protocol: see [`../../docs/EMBEDDED_IFRAME_PROTOCOL.md`](../../docs/EMBEDDED_IFRAME_PROTOCOL.md).
- The OAuth client must have **Embedded iframe login** and **parent origins** set; for v2, enable **Embedded protocol v2** in the admin UI.

## Install

```bash
npm i @auth-service/embedded-auth
```

(Or `workspace:`-link the package from a monorepo checkout.)

## Usage

```ts
import { createEmbeddedAuth } from "@auth-service/embedded-auth";

const { iframe, load, initHandshake, destroy, updateTheme, logout } = createEmbeddedAuth({
  issuer: "https://auth.example.com",
  clientId: "myclient",
  allowedMessageOrigins: ["https://app.example.com", "https://auth.example.com"],
  onSuccess: (payload) => {
    // BFF: `embedded_session_code` from iframe (`AUTH_SUCCESS`); legacy: `access_token` only.
    if (payload.embedded_session_code) {
      // POST to your backend with `grant_type=embedded_session` …
      return;
    }
    // …
  },
  onError: (e) => console.warn(e),
  onReady: () => {
    initHandshake();
  },
});

document.getElementById("auth-slot")?.append(iframe);
load();
```

## Build

```bash
cd sdk/embedded-auth && npm i && npm run build
```
