# EncryptService

EncryptService cifra y descifra objetos JSON para la aplicación web y para las integraciones entre backends. Usa cifrado híbrido: RSA-OAEP con SHA-256 protege una llave AES-256 aleatoria y AES-256-GCM cifra el contenido.

Cada operación devuelve el ciphertext en un solo campo:

```json
{ "data": "<cadena Base64 compacta>" }
```

La cadena Base64 contiene, en orden, una versión de formato (`0x01`), dos bytes con la longitud de la llave RSA envuelta, la llave AES envuelta, el IV de 12 bytes y el ciphertext con la etiqueta GCM. Así el vector y el resto del sobre viajan juntos en `data`.

## Dos alcances aislados

El servicio mantiene un par RSA y un token distintos para cada alcance:

| Alcance | Llave pública | Llave privada | Token |
| --- | --- | --- | --- |
| Web | `crypto.web-rsa.public-key-spki-base64` | Solo en EncryptService | `crypto.web-token` |
| Back-to-back | `crypto.rsa.public-key-spki-base64` | Solo en EncryptService | `crypto.service-token` |

El token web puede llegar al navegador mediante `/cryptoService/web/config`. Solo autoriza endpoints web y no permite descifrar contenido cifrado para la llave pública de servicio. La llave privada y el token de servicio nunca se entregan al navegador. Todos los endpoints que cifran o descifran requieren el token de su alcance en `X-Web-Token` o `X-Service-Token`.

## Endpoints

Las rutas de llave pública no requieren token:

- `GET /cryptoService/public-key`: devuelve `{ "publicKeyBase64": "..." }` para integraciones B2B.
- `GET /cryptoService/web/public-key`: devuelve la llave pública web.
- `GET /cryptoService/web/config`: devuelve la llave pública web y `webToken`; se usa en la demo del navegador.

Las operaciones de servicio requieren `X-Service-Token`:

- `POST /cryptoService/encrypt`: cifra el JSON de `data` para la llave pública de servicio. Puede incluir `recipientPublicKey` para cifrar la respuesta de una aplicación a una llave RSA efímera.
- `POST /cryptoService/decrypt`: recibe `data` como cadena Base64 y devuelve el JSON descifrado. Está pensado para el backend que debe procesar el contenido.

Las operaciones web requieren `X-Web-Token`:

- `POST /cryptoService/web/encrypt`: cifra el JSON de `data` con la llave web o con `recipientPublicKey` si se envía.
- `POST /cryptoService/web/decrypt`: descifra un valor de alcance web y devuelve el JSON claro para que un backend autorizado procese su contenido.
- `POST /cryptoService/web/decrypt-for-client`: descifra `data` y vuelve a cifrar el resultado para `recipientPublicKey`. La respuesta es `{ "data": "<ciphertext Base64>" }`; este es el endpoint que usa la demo para que el navegador pueda mostrar el resultado sin recibirlo en claro por HTTP.

Ejemplo de request de descifrado:

```json
{ "data": "<cadena Base64 compacta>" }
```

Ejemplo de cifrado para una llave efímera:

```json
{
  "data": { "mensaje": "contenido" },
  "recipientPublicKey": "<SPKI Base64 del destinatario>"
}
```

## Demo web

La página `/` tiene dos flujos:

1. **Cifrar:** carga la llave pública y el token web, cifra el JSON localmente en el navegador y muestra la cadena compacta lista para enviar en `data`.
2. **Descifrar:** el navegador genera un par RSA efímero y envía el ciphertext, la llave pública efímera y `X-Web-Token` a `/cryptoService/web/decrypt-for-client`. EncryptService descifra con la llave web y cifra la respuesta para la llave efímera. El navegador la descifra localmente. La sección «JSON descifrado» aparece solo después de un descifrado exitoso.

## Secretos y ejecución

`application-secrets.yml` está excluido de Git y debe existir junto al proyecto en local o montarse en `/app/application-secrets.yml` en Docker. Contiene la configuración con esta estructura:

```yaml
crypto:
  rsa:
    private-key-pkcs8-base64: "<llave privada PKCS8 Base64 del alcance B2B>"
    public-key-spki-base64: "<llave pública SPKI Base64 del alcance B2B>"
  web-rsa:
    private-key-pkcs8-base64: "<llave privada PKCS8 Base64 del alcance web>"
    public-key-spki-base64: "<llave pública SPKI Base64 del alcance web>"
  service-token: "<token aleatorio B2B>"
  web-token: "<token aleatorio web distinto>"
```

Cada par RSA debe coincidir y tener al menos 3072 bits. Conserva las dos llaves privadas solo en EncryptService. Copia cada token únicamente a los backends que usan su alcance; nunca reutilices el token web como token de servicio. En despliegue, sirve el servicio por HTTPS.

La aplicación escucha en el puerto `8080` por defecto (`SERVER_PORT` lo puede cambiar). Para ejecutar localmente con Maven:

```powershell
mvn spring-boot:run
```

Para desplegar con Docker Compose, el archivo `application-secrets.yml` se monta como solo lectura y el servicio expone el puerto interno `8080` a la red `homelab`.
