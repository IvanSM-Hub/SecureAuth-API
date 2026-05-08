package com.ivansario.secureauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityPassEncoderConfig {

    @Bean
    PasswordEncoder passwordEncoder() {return new BCryptPasswordEncoder();}

}
