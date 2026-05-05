package com.ivansario.secureauth.security;

import org.springframework.beans.factory.annotation.Value;

public class JwtUtil {

    @Value("${JWT_SECRET_KEY}")
    private String jwtSecret;

}
