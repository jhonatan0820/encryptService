# EncryptService

EncryptService provides the shared encryption API used by the EncryptService
and TokenService web clients, backend integrations, and Postman. All API input
and output is carried in a root `data` property. The encrypt and decrypt routes
do not require authorization headers.

## Current envelope

New values use envelope v4 with AES-256-GCM, a random 96-bit IV, a 128-bit
authentication tag, and context `GLOB`. The complete envelope is Base64 encoded
as one string:

```json
{ "data": "<Base64 ciphertext>" }
```

The envelope's key ID selects the cryptographic profile. `RSA1` uses the
general public/private RSA pair for requests and backend traffic. `ENCR` and
`TOKN` use separate RSA pairs for the EncryptService and TokenService browser
clients. Web responses use the matching AES key ID, so the browser's existing
backend decrypt bridge can open the response without receiving any private key.

## API

### Public key

`GET /api/crypto/public-key` returns the general RSA public key.
`GET /api/crypto/public-key?profile=ENCR` returns the EncryptService web
public key, and `?profile=TOKN` returns the TokenService web public key.
Public keys can be shared; private keys remain in EncryptService.

### Encrypt

`POST /api/crypto/encrypt` accepts JSON under `data` and returns the
ciphertext under `data`:

```json
{ "data": { "mensaje": "prueba", "cantidad": 12 } }
```

Ordinary requests use the active global AES key. TokenService marks a web
response profile inside `data` so EncryptService uses that profile's AES key:

```json
{
  "data": {
    "__crypto": { "profile": "TOKN" },
    "payload": { "mensaje": "respuesta web" }
  }
}
```

The response remains `{ "data": "<Base64 ciphertext>" }`.

### Decrypt

`POST /api/crypto/decrypt` accepts the complete ciphertext string and returns
the original JSON value under `data`. The service selects the matching private
RSA or AES key from the envelope itself:

```json
{ "data": "<Base64 ciphertext>" }
```

It also accepts the JSON response from `/encrypt` as input to this page's web
form; the form extracts its `data` value before calling the endpoint.

## Web clients

The EncryptService demo encrypts locally with the `ENCR` public key. Its
**Descifrar** form calls `/api/crypto/decrypt` and displays the returned JSON.
The TokenService browser uses the `TOKN` public key and continues to decrypt
responses through `/tokenService/decrypt` on TokenService. TokenService tells
EncryptService which AES profile to use by placing the profile marker inside
the `data` body. Neither browser receives private RSA keys or AES keys.

## Postman

For a local EncryptService on port 8080, use:

```powershell
curl.exe --url "http://localhost:8080/api/crypto/encrypt" `
  --header "Content-Type: application/json" `
  --data-raw '{"data":{"mensaje":"prueba","cantidad":12}}'
```

Copy the returned ciphertext string and decrypt it:

```powershell
curl.exe --url "http://localhost:8080/api/crypto/decrypt" `
  --header "Content-Type: application/json" `
  --data-raw '{"data":"PEGA_AQUI_EL_CIPHERTEXT"}'
```

No token or cryptographic header is required. Postman can decrypt envelopes
from any service that uses this shared EncryptService keyring.

## Configuration

Mount `application-secrets.yml` read-only. Keep this file out of Git. It must
contain the global RSA pair, distinct RSA pairs for both web clients, and an
AES key for each active profile:

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

For local execution, run `mvn spring-boot:run`. Docker Compose mounts the
secrets file at `/app/application-secrets.yml` and exposes the application on
the `homelab` network. The service requires Java 17 and Maven.
