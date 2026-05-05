package com.ivansario.secureauth.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    @Value("${JWT_SECRET_KEY}")
    private String jwtSecret;

}
