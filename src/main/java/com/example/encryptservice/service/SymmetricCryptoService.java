package com.example.encryptservice.service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SymmetricCryptoService {
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private final SecretKeySpec serviceKey;
    private final SecretKeySpec webKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public SymmetricCryptoService(
            @Value("${crypto.aes.service-key}") String serviceKeyBase64,
            @Value("${crypto.aes.web-key}") String webKeyBase64) {
        this.serviceKey = loadKey(serviceKeyBase64, "crypto.aes.service-key");
        this.webKey = loadKey(webKeyBase64, "crypto.aes.web-key");
    }

    private SecretKeySpec loadKey(String keyBase64, String propertyName) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
            if (keyBytes.length != 32) {
                throw new IllegalArgumentException("La clave AES debe tener exactamente 32 bytes");
            }
            return new SecretKeySpec(keyBytes, "AES");
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(propertyName + " debe ser Base64 de una clave AES-256 válida", e);
        }
    }

    public EncryptedPayload encrypt(String plainText, KeyScope scope) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_BYTES];
        secureRandom.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyFor(scope), new GCMParameterSpec(TAG_BITS, nonce));
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] payload = new byte[nonce.length + encrypted.length];
        System.arraycopy(nonce, 0, payload, 0, nonce.length);
        System.arraycopy(encrypted, 0, payload, nonce.length, encrypted.length);
        return new EncryptedPayload(Base64.getEncoder().encodeToString(payload));
    }

    public String decrypt(String payloadBase64, KeyScope scope) throws GeneralSecurityException {
        byte[] payload = Base64.getDecoder().decode(payloadBase64);
        if (payload.length < NONCE_BYTES + TAG_BITS / 8) {
            throw new IllegalArgumentException("El contenido cifrado es demasiado corto");
        }
        byte[] nonce = java.util.Arrays.copyOfRange(payload, 0, NONCE_BYTES);
        byte[] encrypted = java.util.Arrays.copyOfRange(payload, NONCE_BYTES, payload.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keyFor(scope), new GCMParameterSpec(TAG_BITS, nonce));
        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
    }

    private SecretKeySpec keyFor(KeyScope scope) {
        return scope == KeyScope.WEB ? webKey : serviceKey;
    }

    public enum KeyScope { SERVICE, WEB }
    public record EncryptedPayload(String data) {}
}
