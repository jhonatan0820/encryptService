package com.example.encryptservice.config;

import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "crypto.aes")
public record AesKeyProperties(String activeKeyId, Map<String, String> keys) { }
