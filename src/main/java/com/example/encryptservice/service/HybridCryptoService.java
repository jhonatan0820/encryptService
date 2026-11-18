package com.example.encryptservice.service;

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
    private static final int SERVICE_CODE_BYTES = 4;
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    private final KeyPair serviceKeys;
    private final KeyPair webKeys;
    private final String serviceToken;
    private final String webToken;
    private final ObjectMapper mapper;
    private final SecureRandom random = new SecureRandom();

    public HybridCryptoService(
            @Value("${crypto.rsa.private-key-pkcs8-base64}") String servicePrivate,
            @Value("${crypto.rsa.public-key-spki-base64}") String servicePublic,
            @Value("${crypto.web-rsa.private-key-pkcs8-base64}") String webPrivate,
            @Value("${crypto.web-rsa.public-key-spki-base64}") String webPublic,
            @Value("${crypto.service-token}") String serviceToken,
            @Value("${crypto.web-token}") String webToken,
            ObjectMapper mapper) {
        this.serviceKeys = loadPair(servicePrivate, servicePublic, "service");
        this.webKeys = loadPair(webPrivate, webPublic, "web");
        if (serviceToken == null || serviceToken.isBlank() || webToken == null || webToken.isBlank())
            throw new IllegalStateException("Los tokens de servicio y web son obligatorios");
        if (serviceToken.equals(webToken)) throw new IllegalStateException("Los tokens web y de servicio deben ser distintos");
        this.serviceToken = serviceToken;
        this.webToken = webToken;
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
    public String publicKeyBase64(Scope scope) {
        return Base64.getEncoder().encodeToString(keyPair(scope).getPublic().getEncoded());
    }
    public String webToken() { return webToken; }
    public boolean acceptsToken(String supplied, Scope scope) {
        if (supplied == null) return false;
        String expected = scope == Scope.WEB ? webToken : serviceToken;
        return java.security.MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8));
    }

    public String encrypt(JsonNode data, String recipientPublicKeyBase64, Scope scope)
            throws GeneralSecurityException, com.fasterxml.jackson.core.JsonProcessingException {
        KeyPair target = keyPair(scope);
        PublicKey recipient = recipientPublicKeyBase64 == null || recipientPublicKeyBase64.isBlank()
                ? target.getPublic() : KeyFactory.getInstance("RSA").generatePublic(
                        new X509EncodedKeySpec(Base64.getDecoder().decode(recipientPublicKeyBase64)));
        if (!(recipient instanceof RSAKey rsaKey) || rsaKey.getModulus().bitLength() < 2048)
            throw new IllegalArgumentException("La llave receptora debe ser RSA de al menos 2048 bits");
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, random);
        SecretKey aesKey = generator.generateKey();
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(TAG_BITS, iv));
        byte[] ciphertext = aes.doFinal(mapper.writeValueAsBytes(data));
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, recipient, OAEP);
        byte[] wrappedKey = rsa.doFinal(aesKey.getEncoded());
        if (wrappedKey.length > 0xffff) throw new IllegalArgumentException("Llave RSA demasiado larga");
        ByteBuffer packed = ByteBuffer.allocate(HEADER_BYTES + wrappedKey.length + IV_BYTES + ciphertext.length);
        packed.put(FORMAT_VERSION).putShort((short) wrappedKey.length).put(wrappedKey).put(iv).put(ciphertext);
        return Base64.getEncoder().encodeToString(packed.array());
    }

    /** AES-GCM envelope keyed by a service-specific key derived from the service token. */
    public String encryptForService(JsonNode data, String serviceCode)
            throws GeneralSecurityException, com.fasterxml.jackson.core.JsonProcessingException {
        byte[] code = validateServiceCode(serviceCode);
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        byte[] aad = ByteBuffer.allocate(1 + SERVICE_CODE_BYTES).put(SERVICE_AES_VERSION).put(code).array();
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, serviceKey(code), new GCMParameterSpec(TAG_BITS, iv));
        aes.updateAAD(aad);
        byte[] ciphertext = aes.doFinal(mapper.writeValueAsBytes(data));
        ByteBuffer packed = ByteBuffer.allocate(aad.length + IV_BYTES + ciphertext.length);
        packed.put(aad).put(iv).put(ciphertext);
        return Base64.getEncoder().encodeToString(packed.array());
    }

    public JsonNode decrypt(String encryptedValue, Scope scope) throws GeneralSecurityException, java.io.IOException {
        return decrypt(encryptedValue, scope, null);
    }

    public JsonNode decrypt(String encryptedValue, Scope scope, String expectedServiceCode) throws GeneralSecurityException, java.io.IOException {
        byte[] packed = Base64.getDecoder().decode(encryptedValue);
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
            aes.init(Cipher.DECRYPT_MODE, serviceKey(code), new GCMParameterSpec(TAG_BITS, iv));
            aes.updateAAD(aad);
            return mapper.readTree(aes.doFinal(ciphertext));
        }
        if (packed.length <= HEADER_BYTES + IV_BYTES + TAG_BITS / 8 || packed[0] != FORMAT_VERSION)
            throw new IllegalArgumentException("Sobre cifrado inválido");
        ByteBuffer input = ByteBuffer.wrap(packed);
        input.get();
        int wrappedLength = Short.toUnsignedInt(input.getShort());
        if (wrappedLength == 0 || input.remaining() < wrappedLength + IV_BYTES + TAG_BITS / 8)
            throw new IllegalArgumentException("Sobre cifrado truncado");
        byte[] wrappedKey = new byte[wrappedLength]; input.get(wrappedKey);
        byte[] iv = new byte[IV_BYTES]; input.get(iv);
        byte[] ciphertext = new byte[input.remaining()]; input.get(ciphertext);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.DECRYPT_MODE, keyPair(scope).getPrivate(), OAEP);
        byte[] rawAesKey = rsa.doFinal(wrappedKey);
        if (rawAesKey.length != 32) throw new IllegalArgumentException("Clave AES inválida");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawAesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        return mapper.readTree(aes.doFinal(ciphertext));
    }

    private SecretKey serviceKey(byte[] code) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(serviceToken.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        mac.update("EncryptService/AES-GCM/v2/".getBytes(StandardCharsets.US_ASCII));
        return new SecretKeySpec(mac.doFinal(code), "AES");
    }

    private static byte[] validateServiceCode(String value) {
        if (value == null || !value.matches("[A-Z]{4}"))
            throw new IllegalArgumentException("X-Service-Code debe contener exactamente cuatro letras mayúsculas");
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private KeyPair keyPair(Scope scope) { return scope == Scope.WEB ? webKeys : serviceKeys; }
}


