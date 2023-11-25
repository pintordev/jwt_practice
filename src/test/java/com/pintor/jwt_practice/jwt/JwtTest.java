package com.pintor.jwt_practice.jwt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class JwtTest {

    @Value("custom.jwt.secretKey")
    private String secretKey;

    @Test
    @DisplayName("jwt secret key test")
    public void t1() throws Exception {

        assertThat(this.secretKey).isNotNull();
    }
}
