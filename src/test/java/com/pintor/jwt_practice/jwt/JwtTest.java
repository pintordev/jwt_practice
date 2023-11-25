package com.pintor.jwt_practice.jwt;

import com.pintor.jwt_practice.base.jwt.JwtProvider;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import javax.crypto.SecretKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class JwtTest {

    // "${properties.key}"
    @Value("${custom.jwt.secretKey}")
    private String originalKey;

    @Autowired
    private JwtProvider jwtProvider;

    @Test
    @DisplayName("jwt secret key test")
    public void t1() throws Exception {

        // 입력받은 값이 null이 아닌지 여부를 반환한다
        assertThat(this.originalKey).isNotNull();
    }

    @Test
    @DisplayName("make secretKey from originalKey using hmac encryption algorithm")
    public void t2() throws Exception {

        // 입력받은 문자열을 Base64 방식으로 인코딩 한다
        String keyBase64Encoded = Base64.getEncoder().encodeToString(this.originalKey.getBytes());

        // Base64 방식으로 인코딩 된 문자열을 hmac 암호화 알고리듬을 이용해 secretKey를 만든다
        SecretKey secretKey = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());

        assertThat(secretKey).isNotNull();
    }

    @Test
    @DisplayName("make secretKey using jwtProvider")
    public void t3() throws Exception {

        SecretKey secretKey = this.jwtProvider.getSecretKey();

        assertThat(secretKey).isNotNull();
    }

    @Test
    @DisplayName("secretKey must be generated only once")
    public void t4() throws Exception {

        SecretKey secretKey1 = this.jwtProvider.getSecretKey();
        SecretKey secretKey2 = this.jwtProvider.getSecretKey();

        assertThat(secretKey1 == secretKey2).isTrue();
    }
}
