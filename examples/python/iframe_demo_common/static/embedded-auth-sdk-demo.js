/*
 * Minimal browser SDK adapter for the Python iframe demo.
 * Mirrors the createEmbeddedAuth API from sdk/embedded-auth.
 */
(function (global) {
  function joinUrl(issuer, path) {
    return issuer.replace(/\/$/, "") + (path.charAt(0) === "/" ? path : "/" + path);
  }

  function createEmbeddedAuth(options) {
    var iframe = document.createElement("iframe");
    iframe.setAttribute("title", "Auth login");
    iframe.style.width = "100%";
    iframe.style.minHeight = "400px";
    iframe.style.border = "1px solid #ccc";
    iframe.style.borderRadius = "8px";

    var allowed = new Set(options.allowedMessageOrigins || []);

    function safeJson(raw) {
      if (raw == null) return null;
      if (typeof raw === "string") {
        try {
          return JSON.parse(raw);
        } catch (e) {
          return null;
        }
      }
      return raw;
    }

    function onMessage(ev) {
      if (ev.source !== iframe.contentWindow) return;
      if (!ev.origin || !allowed.has(ev.origin)) return;

      var data = safeJson(ev.data);
      if (!data || typeof data !== "object") return;

      if (data.v === 1 && data.type === "EMBED_READY" && options.onReady) {
        options.onReady(data);
      }
      if (data.v === 1 && data.type === "SESSION_ENDED" && options.onSessionEnded) {
        options.onSessionEnded(data);
      }
      // Auth Service strips refresh_token from iframe JSON; postMessage only has access_token.
      if (data.type === "AUTH_SUCCESS" && data.access_token) {
        if (options.onSuccess) {
          options.onSuccess({
            access_token: String(data.access_token),
            refresh_token: data.refresh_token != null ? String(data.refresh_token) : "",
          });
        }
        return;
      }
      if (data.type === "AUTH_ERROR" && options.onError) {
        options.onError({
          error: String(data.error || "AUTH_ERROR"),
          message: String(data.message || ""),
          raw: data,
        });
      }
    }

    function load() {
      var src = new URL(joinUrl(options.issuer, "/embedded-login"));
      src.searchParams.set("client_id", options.clientId);
      iframe.src = src.toString();
    }

    function send(type, extra) {
      if (!iframe.contentWindow) return;
      var payload = Object.assign(
        {
          v: 1,
          type: type,
          ts: Math.floor(Date.now() / 1000),
          source: "parent_sdk",
          nonce:
            global.crypto && typeof global.crypto.randomUUID === "function"
              ? global.crypto.randomUUID()
              : String(Math.random()) + String(Date.now()),
        },
        extra || {}
      );
      var target = iframe.src && iframe.src !== "about:blank" ? new URL(iframe.src).origin : new URL(options.issuer).origin;
      iframe.contentWindow.postMessage(payload, target);
    }

    function destroy() {
      global.removeEventListener("message", onMessage);
      iframe.remove();
    }

    global.addEventListener("message", onMessage);

    return {
      iframe: iframe,
      load: load,
      destroy: destroy,
      initHandshake: function () {
        send("INIT");
      },
      updateTheme: function (theme) {
        send("THEME_UPDATE", { theme: theme });
      },
      logout: function () {
        send("LOGOUT");
      },
    };
  }

  global.EmbeddedAuthSdkDemo = {
    createEmbeddedAuth: createEmbeddedAuth,
  };
})(window);
