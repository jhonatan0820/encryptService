package com.example.encryptservice.controller;

import com.example.encryptservice.service.SymmetricCryptoService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.security.GeneralSecurityException;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/cryptoService")
public class CryptoController {
    private final SymmetricCryptoService cryptoService;
    private final ObjectMapper objectMapper;

    public CryptoController(SymmetricCryptoService cryptoService, ObjectMapper objectMapper) {
        this.cryptoService = cryptoService;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/encrypt")
    public CipherResponse encrypt(@Valid @RequestBody EncryptRequest request) {
        return encrypt(request, SymmetricCryptoService.KeyScope.SERVICE);
    }

    @PostMapping("/web/encrypt")
    public CipherResponse encryptFromWeb(@Valid @RequestBody EncryptRequest request) {
        return encrypt(request, SymmetricCryptoService.KeyScope.WEB);
    }

    private CipherResponse encrypt(EncryptRequest request, SymmetricCryptoService.KeyScope scope) {
        try {
            String json = objectMapper.writeValueAsString(request.data());
            var payload = cryptoService.encrypt(json, scope);
            return new CipherResponse(payload.data());
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El objeto data no se pudo serializar", e);
        } catch (GeneralSecurityException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al cifrar", e);
        }
    }

    @PostMapping("/decrypt")
    public DataResponse decrypt(@Valid @RequestBody DecryptRequest request) {
        return decrypt(request, SymmetricCryptoService.KeyScope.SERVICE);
    }

    @PostMapping("/web/decrypt")
    public ResponseEntity<?> decryptFromWeb(@Valid @RequestBody DecryptRequest request) {
        try {
            return ResponseEntity.ok(decrypt(request, SymmetricCryptoService.KeyScope.WEB));
        } catch (ResponseStatusException e) {
            if (e.getStatusCode().value() == HttpStatus.BAD_REQUEST.value()) {
                return ResponseEntity.badRequest().body(new ErrorResponse("Objeto cifrado corrupto"));
            }
            throw e;
        }
    }

    private DataResponse decrypt(DecryptRequest request, SymmetricCryptoService.KeyScope scope) {
        try {
            String json = cryptoService.decrypt(request.data(), scope);
            return new DataResponse(objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {}));
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Texto cifrado inválido", e);
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El contenido descifrado no es un objeto JSON", e);
        }
    }

    public record EncryptRequest(@NotNull Map<String, Object> data) {}
    public record DecryptRequest(@NotBlank String data) {}
    public record CipherResponse(String data) {}
    public record DataResponse(Map<String, Object> data) {}
    public record ErrorResponse(String message) {}
}
