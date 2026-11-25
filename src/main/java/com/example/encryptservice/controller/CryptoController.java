package com.example.encryptservice.controller;

import com.example.encryptservice.service.HybridCryptoService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {
    private final HybridCryptoService crypto;
    public CryptoController(HybridCryptoService crypto) { this.crypto = crypto; }

    @GetMapping("/public-key")
    public ResponseEntity<Map<String, String>> publicKey(
            @RequestParam(defaultValue = "GLOBAL") String profile) {
        String key = "GLOBAL".equals(profile)
                ? crypto.publicKeyBase64()
                : crypto.publicKeyBase64(profile);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(Map.of("publicKeyBase64", key));
    }

    @PostMapping("/encrypt")
    public CipherResponse encrypt(@Valid @RequestBody EncryptRequest request) {
        try {
            JsonNode data = request.data();
            String profile = "GLOBAL";
            JsonNode cryptoMeta = data.path("__crypto");
            if (!cryptoMeta.isMissingNode()) {
                JsonNode profileNode = cryptoMeta.path("profile");
                if (!data.isObject() || !profileNode.isTextual() || !data.has("payload"))
                    throw new IllegalArgumentException("Metadatos de perfil web inválidos");
                profile = profileNode.asText();
                data = data.get("payload");
            }
            String encrypted = crypto.encryptForProfile(data, profile);
            return new CipherResponse(encrypted);
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo cifrar el objeto", ex);
        }
    }

    @PostMapping("/decrypt")
    public DataResponse decrypt(@Valid @RequestBody DecryptRequest request) {
        try { return new DataResponse(crypto.decrypt(request.data())); }
        catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Objeto cifrado inválido", ex);
        }
    }

    public record EncryptRequest(@NotNull JsonNode data) { }
    public record DecryptRequest(@NotBlank String data) { }
    public record CipherResponse(String data) { }
    public record DataResponse(JsonNode data) { }
}
