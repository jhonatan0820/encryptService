package com.example.encryptservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.example.encryptservice.config.AesKeyProperties;

@SpringBootApplication
@EnableConfigurationProperties(AesKeyProperties.class)
public class EncryptServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(EncryptServiceApplication.class, args);
    }
}
