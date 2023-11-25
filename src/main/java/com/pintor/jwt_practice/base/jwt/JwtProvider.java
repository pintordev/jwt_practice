package com.pintor.jwt_practice.base.jwt;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;

@Component
public class JwtProvider {

    @Value("${custom.jwt.secretKey}")
    private String originalKey;

    public SecretKey getSecretKey() {

        String keyBase64Encoded = Base64.getEncoder().encodeToString(this.originalKey.getBytes());

        return Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
    }
}