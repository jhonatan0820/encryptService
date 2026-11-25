package com.example.encryptservice.service;

import com.example.encryptservice.config.AesKeyProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import javax.crypto.Mac;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class HybridCryptoService {
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int HEADER_BYTES = 3;
    private static final byte FORMAT_VERSION = 1;
    private static final byte SERVICE_AES_VERSION = 2;
    private static final byte LEGACY_AES_ENVELOPE_VERSION = 3;
    private static final byte GLOBAL_ENVELOPE_VERSION = 4;
    private static final String GLOBAL_CONTEXT = "GLOB";
    private static final int SERVICE_CODE_BYTES = 4;
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    private final KeyPair serviceKeys;
    private final KeyPair webKeys;
    private final Map<String, KeyPair> webProfiles;
    private final String legacyServiceToken;
    private final String activeAesKeyId;
    private final Map<String, SecretKey> aesKeys;
    private final ObjectMapper mapper;
    private final SecureRandom random = new SecureRandom();

    public HybridCryptoService(
            @Value("${crypto.rsa.private-key-pkcs8-base64}") String servicePrivate,
            @Value("${crypto.rsa.public-key-spki-base64}") String servicePublic,
            @Value("${crypto.web-rsa.private-key-pkcs8-base64:${crypto.rsa.private-key-pkcs8-base64}}") String webPrivate,
            @Value("${crypto.web-rsa.public-key-spki-base64:${crypto.rsa.public-key-spki-base64}}") String webPublic,
            @Value("${crypto.web-rsa.profiles.encryptservice.private-key-pkcs8-base64}") String encryptWebPrivate,
            @Value("${crypto.web-rsa.profiles.encryptservice.public-key-spki-base64}") String encryptWebPublic,
            @Value("${crypto.web-rsa.profiles.tokenservice.private-key-pkcs8-base64}") String tokenWebPrivate,
            @Value("${crypto.web-rsa.profiles.tokenservice.public-key-spki-base64}") String tokenWebPublic,
            @Value("${crypto.legacy.service-token:${crypto.service-token:}}") String legacyServiceToken,
            AesKeyProperties aesKeyProperties,
            ObjectMapper mapper) {
        this.serviceKeys = loadPair(servicePrivate, servicePublic, "service");
        this.webKeys = loadPair(webPrivate, webPublic, "web");
        this.webProfiles = Map.of(
                "ENCR", loadPair(encryptWebPrivate, encryptWebPublic, "EncryptService web"),
                "TOKN", loadPair(tokenWebPrivate, tokenWebPublic, "TokenService web"));
        this.legacyServiceToken = legacyServiceToken;
        this.aesKeys = loadAesKeys(aesKeyProperties);
        this.activeAesKeyId = aesKeyProperties.activeKeyId();
        this.mapper = mapper;
    }

    private KeyPair loadPair(String privateValue, String publicValue, String scope) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            var privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateValue)));
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicValue)));
            if (!(privateKey instanceof RSAKey privateRsa) || !(publicKey instanceof RSAKey publicRsa)
                    || privateRsa.getModulus().bitLength() < 3072
                    || !privateRsa.getModulus().equals(publicRsa.getModulus()))
                throw new IllegalArgumentException("El par " + scope + " debe coincidir y tener al menos 3072 bits");
            return new KeyPair(publicKey, privateKey);
        } catch (Exception ex) {
            throw new IllegalStateException("El par RSA " + scope + " configurado no es válido", ex);
        }
    }

    public enum Scope { SERVICE, WEB }
    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(serviceKeys.getPublic().getEncoded());
    }
    public String publicKeyBase64(String profile) {
        KeyPair pair = webProfiles.get(profile);
        if (pair == null) throw new IllegalArgumentException("Perfil web desconocido");
        return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    }
    public String encryptForServer(JsonNode data)
            throws GeneralSecurityException, com.fasterxml.jackson.core.JsonProcessingException {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, random);
        SecretKey aesKey = generator.generateKey();
        rsa.init(Cipher.ENCRYPT_MODE, serviceKeys.getPublic(), OAEP);
        byte[] wrappedKey = rsa.doFinal(aesKey.getEncoded());
        return encryptAesEnvelope(data, aesKey, GLOBAL_CONTEXT, "RSA1", wrappedKey);
    }

    /** AES-GCM v3 envelope keyed from the central AES keyring and service context. */
    public String encryptForService(JsonNode data)
            throws GeneralSecurityException, com.fasterxml.jackson.core.JsonProcessingException {
        return encryptAesEnvelope(data, globalKey(activeAesKeyId), GLOBAL_CONTEXT, activeAesKeyId);
    }

    public String encryptForProfile(JsonNode data, String profile)
            throws GeneralSecurityException, com.fasterxml.jackson.core.JsonProcessingException {
        if (profile == null || profile.isBlank() || "GLOBAL".equals(profile)) return encryptForService(data);
        if (!webProfiles.containsKey(profile)) throw new IllegalArgumentException("Perfil web desconocido");
        return encryptAesEnvelope(data, globalKey(profile), GLOBAL_CONTEXT, profile);
    }

    /** Compatibility overload: new envelopes use the single global context. */
    public String encryptForService(JsonNode data, String ignoredServiceCode)
            throws GeneralSecurityException, com.fasterxml.jackson.core.JsonProcessingException {
        return encryptForService(data);
    }

    public JsonNode decrypt(String encryptedValue) throws GeneralSecurityException, java.io.IOException {
        byte[] packed = Base64.getDecoder().decode(encryptedValue);
        if (packed.length > 0 && packed[0] == GLOBAL_ENVELOPE_VERSION)
            return decryptGlobalEnvelope(packed);
        return decrypt(encryptedValue, Scope.SERVICE, null);
    }

    public JsonNode decrypt(String encryptedValue, Scope scope) throws GeneralSecurityException, java.io.IOException {
        return decrypt(encryptedValue, scope, null);
    }

    public JsonNode decrypt(String encryptedValue, Scope scope, String expectedServiceCode) throws GeneralSecurityException, java.io.IOException {
        byte[] packed = Base64.getDecoder().decode(encryptedValue);
        if (packed.length > 0 && packed[0] == GLOBAL_ENVELOPE_VERSION)
            return decryptGlobalEnvelope(packed);
        if (packed.length > 0 && packed[0] == LEGACY_AES_ENVELOPE_VERSION) {
            if (scope != Scope.SERVICE)
                throw new IllegalArgumentException("Sobre cifrado de servicio inválido para este alcance");
            ByteBuffer header = ByteBuffer.wrap(packed);
            header.get();
            String serviceCode = readAsciiIdentifier(header);
            byte[] code = validateServiceCode(serviceCode);
            String keyId = readAsciiIdentifier(header);
            SecretKey masterKey = aesKeys.get(keyId);
            if (masterKey == null) throw new IllegalArgumentException("Identificador de llave desconocido");
            if (expectedServiceCode != null && !expectedServiceCode.isBlank() && !expectedServiceCode.equals(serviceCode))
                throw new IllegalArgumentException("El código de servicio no coincide con el sobre");
            return decryptLegacyV3(packed, serviceKey(code, keyId), serviceCode, keyId);
        }
        if (packed.length > 1 && packed[0] == SERVICE_AES_VERSION) {
            if (scope != Scope.SERVICE || packed.length < 1 + SERVICE_CODE_BYTES + IV_BYTES + TAG_BITS / 8)
                throw new IllegalArgumentException("Sobre AES de servicio inválido");
            ByteBuffer input = ByteBuffer.wrap(packed);
            input.get();
            byte[] code = new byte[SERVICE_CODE_BYTES]; input.get(code);
            String codeText = new String(code, StandardCharsets.US_ASCII);
            validateServiceCode(codeText);
            if (expectedServiceCode != null && !expectedServiceCode.isBlank()
                    && !expectedServiceCode.equals(codeText))
                throw new IllegalArgumentException("El código de servicio no coincide con el sobre");
            byte[] iv = new byte[IV_BYTES]; input.get(iv);
            byte[] ciphertext = new byte[input.remaining()]; input.get(ciphertext);
            byte[] aad = ByteBuffer.allocate(1 + SERVICE_CODE_BYTES).put(SERVICE_AES_VERSION).put(code).array();
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, legacyServiceKey(code), new GCMParameterSpec(TAG_BITS, iv));
            aes.updateAAD(aad);
            return mapper.readTree(aes.doFinal(ciphertext));
        }
        if (packed.length <= HEADER_BYTES + IV_BYTES + TAG_BITS / 8 || packed[0] != FORMAT_VERSION)
            throw new IllegalArgumentException("Sobre cifrado inválido");
        ByteBuffer input = ByteBuffer.wrap(packed);
        input.position(1);
        int wrappedLength = Short.toUnsignedInt(input.getShort());
        if (wrappedLength == 0 || input.remaining() < wrappedLength + IV_BYTES + TAG_BITS / 8)
            throw new IllegalArgumentException("Sobre cifrado truncado");
        Exception firstFailure;
        try { return decryptLegacyHybrid(packed, serviceKeys); }
        catch (Exception ex) { firstFailure = ex; }
        try { return decryptLegacyHybrid(packed, webKeys); }
        catch (Exception ex) { ex.addSuppressed(firstFailure); throw ex; }
    }

    private String encryptAesEnvelope(JsonNode data, SecretKey key, String contextId, String keyId)
            throws GeneralSecurityException, com.fasterxml.jackson.core.JsonProcessingException {
        return encryptAesEnvelope(data, key, contextId, keyId, new byte[0]);
    }

    private String encryptAesEnvelope(JsonNode data, SecretKey key, String contextId, String keyId, byte[] wrappedKey)
            throws GeneralSecurityException, com.fasterxml.jackson.core.JsonProcessingException {
        if (data == null || key == null || key.getEncoded() == null || key.getEncoded().length != 32)
            throw new IllegalArgumentException("Payload y llave AES-256 son obligatorios");
        byte[] contextBytes = asciiIdentifier(contextId);
        byte[] keyIdBytes = asciiIdentifier(keyId);
        if (wrappedKey == null || wrappedKey.length > 0xffff)
            throw new IllegalArgumentException("Llave AES envuelta inválida");
        byte[] aad = ByteBuffer.allocate(5 + contextBytes.length + keyIdBytes.length + wrappedKey.length)
                .put(GLOBAL_ENVELOPE_VERSION)
                .put((byte) contextBytes.length).put(contextBytes)
                .put((byte) keyIdBytes.length).put(keyIdBytes)
                .putShort((short) wrappedKey.length).put(wrappedKey).array();
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        aes.updateAAD(aad);
        byte[] ciphertext = aes.doFinal(mapper.writeValueAsBytes(data));
        ByteBuffer packed = ByteBuffer.allocate(aad.length + IV_BYTES + ciphertext.length);
        packed.put(aad).put(iv).put(ciphertext);
        return Base64.getEncoder().encodeToString(packed.array());
    }

    private JsonNode decryptAesEnvelope(byte[] packed, SecretKey key, String expectedContextId, String expectedKeyId)
            throws GeneralSecurityException, java.io.IOException {
        return decryptLegacyV3(packed, key, expectedContextId, expectedKeyId);
    }

    private JsonNode decryptLegacyV3(byte[] packed, SecretKey key, String expectedContextId, String expectedKeyId)
            throws GeneralSecurityException, java.io.IOException {
        ByteBuffer input = ByteBuffer.wrap(packed);
        input.get();
        String contextId = readAsciiIdentifier(input);
        String keyId = readAsciiIdentifier(input);
        if (!expectedContextId.equals(contextId) || !expectedKeyId.equals(keyId))
            throw new IllegalArgumentException("Identificador criptográfico incorrecto");
        int aadLength = input.position();
        if (input.remaining() < IV_BYTES + TAG_BITS / 8)
            throw new IllegalArgumentException("Sobre AES-GCM truncado");
        byte[] aad = java.util.Arrays.copyOfRange(packed, 0, aadLength);
        byte[] iv = new byte[IV_BYTES]; input.get(iv);
        byte[] ciphertext = new byte[input.remaining()]; input.get(ciphertext);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        aes.updateAAD(aad);
        return mapper.readTree(aes.doFinal(ciphertext));
    }

    private JsonNode decryptLegacyHybrid(byte[] packed, KeyPair keyPair)
            throws GeneralSecurityException, java.io.IOException {
        if (packed.length <= HEADER_BYTES + IV_BYTES + TAG_BITS / 8 || packed[0] != FORMAT_VERSION)
            throw new IllegalArgumentException("Sobre híbrido v1 inválido");
        ByteBuffer input = ByteBuffer.wrap(packed);
        input.get();
        int wrappedLength = Short.toUnsignedInt(input.getShort());
        if (wrappedLength == 0 || input.remaining() < wrappedLength + IV_BYTES + TAG_BITS / 8)
            throw new IllegalArgumentException("Sobre híbrido v1 truncado");
        byte[] wrappedKey = new byte[wrappedLength]; input.get(wrappedKey);
        byte[] iv = new byte[IV_BYTES]; input.get(iv);
        byte[] ciphertext = new byte[input.remaining()]; input.get(ciphertext);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), OAEP);
        byte[] rawAesKey = rsa.doFinal(wrappedKey);
        if (rawAesKey.length != 32) throw new IllegalArgumentException("Clave AES inválida");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawAesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        return mapper.readTree(aes.doFinal(ciphertext));
    }

    private JsonNode decryptGlobalEnvelope(byte[] packed) throws GeneralSecurityException, java.io.IOException {
        if (packed == null || packed.length < 5 + IV_BYTES + TAG_BITS / 8
                || packed[0] != GLOBAL_ENVELOPE_VERSION)
            throw new IllegalArgumentException("Sobre global AES-GCM inválido");
        ByteBuffer input = ByteBuffer.wrap(packed);
        input.get();
        String contextId = readAsciiIdentifier(input);
        String keyId = readAsciiIdentifier(input);
        if (!GLOBAL_CONTEXT.equals(contextId))
            throw new IllegalArgumentException("Contexto criptográfico inválido");
        int wrappedLength = Short.toUnsignedInt(input.getShort());
        if (input.remaining() < wrappedLength + IV_BYTES + TAG_BITS / 8)
            throw new IllegalArgumentException("Sobre global truncado");
        byte[] wrappedKey = new byte[wrappedLength]; input.get(wrappedKey);
        SecretKey key;
        if (wrappedLength == 0) key = globalKey(keyId);
        else {
            KeyPair recipient = "RSA1".equals(keyId) ? serviceKeys : webProfiles.get(keyId);
            if (recipient == null) throw new IllegalArgumentException("Identificador de llave RSA inválido");
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.DECRYPT_MODE, recipient.getPrivate(), OAEP);
            byte[] raw = rsa.doFinal(wrappedKey);
            if (raw.length != 32) throw new IllegalArgumentException("Clave AES inválida");
            key = new SecretKeySpec(raw, "AES");
        }
        int aadLength = input.position();
        byte[] aad = java.util.Arrays.copyOfRange(packed, 0, aadLength);
        byte[] iv = new byte[IV_BYTES]; input.get(iv);
        byte[] ciphertext = new byte[input.remaining()]; input.get(ciphertext);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        aes.updateAAD(aad);
        return mapper.readTree(aes.doFinal(ciphertext));
    }

    private SecretKey serviceKey(byte[] code, String keyId) throws GeneralSecurityException {
        SecretKey masterKey = aesKeys.get(keyId);
        if (masterKey == null) throw new IllegalArgumentException("Identificador de llave desconocido");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(masterKey.getEncoded(), "HmacSHA256"));
        mac.update("EncryptService/AES-GCM/v3/".getBytes(StandardCharsets.US_ASCII));
        mac.update(code);
        mac.update((byte) 0);
        mac.update(keyId.getBytes(StandardCharsets.US_ASCII));
        return new SecretKeySpec(mac.doFinal(), "AES");
    }

    private SecretKey globalKey(String keyId) throws GeneralSecurityException {
        SecretKey masterKey = aesKeys.get(keyId);
        if (masterKey == null) throw new IllegalArgumentException("Identificador de llave desconocido");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(masterKey.getEncoded(), "HmacSHA256"));
        mac.update("EncryptService/AES-256-GCM/v4/".getBytes(StandardCharsets.US_ASCII));
        mac.update(GLOBAL_CONTEXT.getBytes(StandardCharsets.US_ASCII));
        mac.update((byte) 0);
        mac.update(keyId.getBytes(StandardCharsets.US_ASCII));
        return new SecretKeySpec(mac.doFinal(), "AES");
    }

    private SecretKey legacyServiceKey(byte[] code) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(legacyServiceToken.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        mac.update("EncryptService/AES-GCM/v2/".getBytes(StandardCharsets.US_ASCII));
        return new SecretKeySpec(mac.doFinal(code), "AES");
    }

    private Map<String, SecretKey> loadAesKeys(AesKeyProperties properties) {
        if (properties == null || properties.activeKeyId() == null || properties.activeKeyId().isBlank()
                || properties.keys() == null || !properties.keys().containsKey(properties.activeKeyId()))
            throw new IllegalStateException("El keyring crypto.aes debe declarar active-key-id y su llave");
        Map<String, SecretKey> loaded = new HashMap<>();
        properties.keys().forEach((id, encoded) -> {
            asciiIdentifier(id);
            try {
                byte[] bytes = Base64.getDecoder().decode(encoded);
                if (bytes.length != 32) throw new IllegalArgumentException("expected 32 bytes");
                loaded.put(id, new SecretKeySpec(bytes, "AES"));
            } catch (Exception ex) {
                throw new IllegalStateException("Llave AES-256 inválida para key id " + id, ex);
            }
        });
        return Map.copyOf(loaded);
    }

    private static String readAsciiIdentifier(ByteBuffer input) {
        if (!input.hasRemaining()) throw new IllegalArgumentException("Sobre truncado");
        int length = Byte.toUnsignedInt(input.get());
        if (length == 0 || input.remaining() < length)
            throw new IllegalArgumentException("Identificador truncado");
        byte[] bytes = new byte[length];
        input.get(bytes);
        String value = new String(bytes, StandardCharsets.US_ASCII);
        if (!java.util.Arrays.equals(bytes, value.getBytes(StandardCharsets.US_ASCII))
                || value.chars().anyMatch(character -> character < 0x21 || character > 0x7e))
            throw new IllegalArgumentException("Identificador no ASCII válido");
        return value;
    }

    private static byte[] asciiIdentifier(String value) {
        if (value == null || value.isEmpty() || value.length() > 32
                || !value.matches("[A-Za-z0-9_-]+"))
            throw new IllegalArgumentException("Identificador criptográfico inválido");
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] validateServiceCode(String value) {
        if (value == null || !value.matches("[A-Z]{4}"))
            throw new IllegalArgumentException("X-Service-Code debe contener exactamente cuatro letras mayúsculas");
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private KeyPair keyPair(Scope scope) { return scope == Scope.WEB ? webKeys : serviceKeys; }
}


