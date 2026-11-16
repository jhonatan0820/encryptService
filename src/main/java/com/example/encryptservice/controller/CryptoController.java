package com.example.encryptservice.controller;

import com.example.encryptservice.service.HybridCryptoService;
import com.example.encryptservice.service.HybridCryptoService.Scope;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/cryptoService")
public class CryptoController {
    private final HybridCryptoService crypto;
    public CryptoController(HybridCryptoService crypto) { this.crypto = crypto; }

    @GetMapping("/public-key") public ResponseEntity<Map<String,String>> serviceKey() {
        return keyResponse(Scope.SERVICE);
    }
    @GetMapping("/web/public-key") public ResponseEntity<Map<String,String>> webKey() {
        return keyResponse(Scope.WEB);
    }
    @GetMapping("/web/config") public ResponseEntity<Map<String,String>> webConfig() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(Map.of("publicKeyBase64", crypto.publicKeyBase64(Scope.WEB), "webToken", crypto.webToken()));
    }
    private ResponseEntity<Map<String,String>> keyResponse(Scope scope) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(Map.of("publicKeyBase64", crypto.publicKeyBase64(scope)));
    }

    @PostMapping("/encrypt") public CipherResponse encryptService(@Valid @RequestBody EncryptRequest request,
            @RequestHeader(value="X-Service-Token", required=false) String token) { return encrypt(request, token, Scope.SERVICE); }
    @PostMapping("/decrypt") public DataResponse decryptService(@Valid @RequestBody DecryptRequest request,
            @RequestHeader(value="X-Service-Token", required=false) String token) { return decrypt(request, token, Scope.SERVICE); }
    @PostMapping("/web/encrypt") public CipherResponse encryptWeb(@Valid @RequestBody EncryptRequest request,
            @RequestHeader(value="X-Web-Token", required=false) String token) { return encrypt(request, token, Scope.WEB); }
    @PostMapping("/web/decrypt") public DataResponse decryptWeb(@Valid @RequestBody DecryptRequest request,
            @RequestHeader(value="X-Web-Token", required=false) String token) { return decrypt(request, token, Scope.WEB); }

    @PostMapping("/web/decrypt-for-client") public CipherResponse decryptForClient(@Valid @RequestBody ClientDecryptRequest request,
            @RequestHeader(value="X-Web-Token", required=false) String token) {
        authorize(token, Scope.WEB);
        try { return new CipherResponse(crypto.encrypt(crypto.decrypt(request.data(), Scope.WEB), request.recipientPublicKey(), Scope.WEB)); }
        catch (Exception ex) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Objeto cifrado inválido", ex); }
    }    private CipherResponse encrypt(EncryptRequest request, String token, Scope scope) {
        authorize(token, scope);
        try { return new CipherResponse(crypto.encrypt(request.data(), request.recipientPublicKey(), scope)); }
        catch (Exception ex) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo cifrar el objeto", ex); }
    }
    private DataResponse decrypt(DecryptRequest request, String token, Scope scope) {
        authorize(token, scope);
        try { return new DataResponse(crypto.decrypt(request.data(), scope)); }
        catch (Exception ex) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Objeto cifrado inválido", ex); }
    }
    private void authorize(String token, Scope scope) {
        if (!crypto.acceptsToken(token, scope)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Integración no autorizada");
    }
    public record EncryptRequest(@NotNull JsonNode data, String recipientPublicKey) {}
    public record DecryptRequest(@NotBlank String data) {}
    public record ClientDecryptRequest(@NotBlank String data, @NotBlank String recipientPublicKey) {}
    public record CipherResponse(String data) {}
    public record DataResponse(JsonNode data) {}
}

