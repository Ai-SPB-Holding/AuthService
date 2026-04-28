# Секреты, JWT-ключи и ротация

## Правила

- **Никогда** не коммитьте в git: приватные RSA-ключи (`.pem`), реальные `.env`, `CLIENT_SECRET` продакшена, `COOKIE_SECRET`, `TOTP__ENCRYPTION_KEY_B64` с прода.
- **JWT RS256**: пара ключей только из секрет-хранилища (Vault, AWS/GCP KMS, Azure Key Vault) или сгенерирована локально и подставлена в окружение при деплое.
- **OAuth client secret**: в БД хранится только **Argon2-хэш**; plaintext показывается администратору **один раз** при создании/ротации.
- **Emergency rotation** при утечке: отозвать старые refresh-сессии (флаг в админке / SQL), сменить JWT key pair (`kid` в JWKS), сменить client secrets, перезаписать `COOKIE_SECRET` и `TOTP` ключ (пользователям — перевыпуск 2FA при необходимости).

## Генерация RSA для локальной разработки

```bash
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
```

PEM в одну строку для `AUTH__JWT_*_KEY_PEM` (с `\n`):

```bash
awk 'NF {sub(/\r$/, ""); printf "%s\\n", $0}' jwt_private.pem
```

## Переменные окружения

См. [`.env.example`](../.env.example): плейсхолдеры `REPLACE_WITH_*` без реальных значений. Реальные ключи — только в secret manager / локальном `.env` (в `.gitignore`).

## Ротация JWT ключей (JWKS)

- Поддерживается `kid` в заголовке JWT; в `/.well-known` и `jwks.json` публикуйте **несколько** ключей в переходный период.
- Порядок: добавить новый ключ → обновить выдачу токенов на новый `kid` → после истечения max TTL access token удалить старый ключ из JWKS.
- Переменные: основной публичный PEM — `AUTH__JWT_PUBLIC_KEY_PEM`; предыдущий (опционально) — `AUTH__JWT_PREVIOUS_PUBLIC_KEY_PEM` и `AUTH__JWT_PREVIOUS_KID` (по умолчанию `rsa-key-0`), чтобы валидировать access-токены, выписанные старым ключом, пока они не истекли.

## Ротация TOTP encryption key

- Основной ключ: `TOTP__ENCRYPTION_KEY_B64`.
- На время миграции: `TOTP__ENCRYPTION_KEY_PREVIOUS_B64` — расшифровка старых записей; при записи используется только текущий ключ.

## Redis и refresh-токены

- В Redis не хранить сырой refresh token в ключе; используется хэш в имени/значении (см. реализацию `auth_service`).
