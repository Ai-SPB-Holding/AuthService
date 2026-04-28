/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_APP_NAME?: string;
  readonly VITE_SSE_URL?: string;
  readonly VITE_DEV_TENANT_ID?: string;
  readonly VITE_DEV_EMAIL?: string;
  readonly VITE_DEV_PASSWORD?: string;
  readonly VITE_DEV_AUDIENCE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
