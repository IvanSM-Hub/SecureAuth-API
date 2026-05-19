package com.ivansario.secureauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ivansario.secureauth.security.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;

/**
 * Configuración de seguridad de Spring Security para la aplicación.
 *
 * Define el filtro JWT, el proveedor de autenticación y la política de sesiones.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {


    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService;
    private final SecurityPassEncoderConfig passEncoderConfig;

    /**
     * Configura la cadena de filtros de seguridad:
     * - Desactiva CSRF
     * - Usa sesiones estateless
     * - Permite endpoints de autenticación y requiere autenticación para el resto
     * - Añade el filtro JWT antes del filtro de autenticación por formulario
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) {
        return http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .authorizeHttpRequests(
            auth -> auth
            .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
            .requestMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated()
        )
        .authenticationProvider(authenticationProvider())
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
    }

    /**
     * Proveedor de autenticación que usa el {@link UserDetailsService} y el encoder de contraseñas.
     */
    @Bean
    AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passEncoderConfig.passwordEncoder());
        return authProvider;
    }
    
    /**
     * Exposición del {@link AuthenticationManager} a partir de la configuración de autenticación.
     */
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

}
