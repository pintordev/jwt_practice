package com.pintor.jwt_practice.base.jwt;

import com.google.gson.Gson;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class JwtProvider {

    @Value("${custom.jwt.secretKey}")
    private String originalKey;

    private SecretKey secretKey;

    private SecretKey genSecretKey() {

        String keyBase64Encoded = Base64.getEncoder().encodeToString(this.originalKey.getBytes());

        return Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
    }

    public SecretKey getSecretKey() {

        if (this.secretKey == null) this.secretKey = this.genSecretKey();

        return this.secretKey;
    }

    public String genToken(Map<String, Object> claims, int seconds) {

        Gson gson = new Gson();
        long now = new Date().getTime(); // milliseconds
        Date tokenExpirationDate = new Date(now + 1000L * seconds); // seconds to milliseconds

        return Jwts.builder()
                .claim("body", gson.toJson(claims))
                .expiration(tokenExpirationDate)
                .signWith(this.getSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }
}