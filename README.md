# EncryptService

EncryptService is the shared encryption and decryption service for browser clients, backend services, and Postman. API values are carried in a root `data` field.

## Cryptographic format

New messages use envelope version 4: AES-256-GCM, a 96-bit IV, a 128-bit authentication tag, and the `GLOB` context. When a client encrypts locally with a published RSA key, RSA-OAEP with SHA-256 wraps the generated AES key. Each envelope identifies the key profile used to process it:

- `RSA1`: the general RSA key pair.
- `ENCR`: the EncryptService browser profile.
- `TOKN`: the TokenService browser profile.
- Ordinary calls to `/api/crypto/encrypt` use the active global AES key.

Profiles are selected from the envelope or the profile marker in `data`. Clients do not send key selectors or credentials in HTTP headers.

## API

All endpoints are below `/api/crypto`.

### `GET /public-key`

Returns the general public key as `{ "publicKeyBase64": "..." }`. Select a browser profile with `?profile=ENCR` or `?profile=TOKN`. Public keys may be shared; private keys must remain in EncryptService.

### `POST /encrypt`

Encrypts the JSON value in `data` and returns a Base64 envelope in `data`:

```json
{
  "data": {
    "message": "sample",
    "quantity": 12
  }
}
```

To encrypt a response for a browser profile, include its marker and the payload:

```json
{
  "data": {
    "__crypto": { "profile": "TOKN" },
    "payload": { "status": "ready" }
  }
}
```

The response is `{ "data": "<Base64 ciphertext>" }`.

### `POST /decrypt`

Accepts the complete envelope as a string and returns the decrypted JSON value under `data`:

```json
{ "data": "<Base64 ciphertext>" }
```

The endpoint selects the matching configured key from the envelope.

## Postman

For a local instance on port 8080:

1. Send a `POST` request to `http://localhost:8080/api/crypto/encrypt`.
2. Select **Body > raw > JSON** and send:

```json
{ "data": { "message": "sample", "quantity": 12 } }
```

3. Copy the returned `data` string.
4. Send a `POST` request to `http://localhost:8080/api/crypto/decrypt` with:

```json
{ "data": "<paste-the-ciphertext>" }
```

No authorization or cryptographic headers are required for these calls. The production base URL is `https://encryptservice.dotacioneszambrano.com`.

## Key configuration

Keep `application-secrets.yml` out of Git. Configure the general RSA pair, both browser RSA pairs, and AES keys for the active global key and browser profiles:

```yaml
crypto:
  rsa:
    private-key-pkcs8-base64: "<global-private-key>"
    public-key-spki-base64: "<global-public-key>"
  web-rsa:
    profiles:
      encryptservice:
        private-key-pkcs8-base64: "<encryptservice-web-private-key>"
        public-key-spki-base64: "<encryptservice-web-public-key>"
      tokenservice:
        private-key-pkcs8-base64: "<tokenservice-web-private-key>"
        public-key-spki-base64: "<tokenservice-web-public-key>"
  aes:
    active-key-id: "2026a"
    keys:
      2026a: "<base64-encoded-32-byte-global-aes-key>"
      ENCR: "<base64-encoded-32-byte-encryptservice-web-aes-key>"
      TOKN: "<base64-encoded-32-byte-tokenservice-web-aes-key>"
```

Each public/private key pair must match. On the homelab, Compose mounts the file selected by `ENCRYPT_SERVICE_SECRETS_PATH` at `/app/application-secrets.yml`; if that variable is unset, it uses `./application-secrets.yml` in the application directory.

## Local development

Requirements: Java 17 and Maven. Place the local secrets file where Spring can load it, then run:

```bash
mvn spring-boot:run
```

Docker Compose connects the container to the external `homelab` network and exposes port 8080 inside that network.
