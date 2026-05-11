package com.ivansario.secureauth.service;

import java.time.LocalDateTime;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserRole;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.exception.InvalidCredentialsException;
import com.ivansario.secureauth.exception.InvalidRefreshTokenException;
import com.ivansario.secureauth.exception.RefreshTokenExpiredException;
import com.ivansario.secureauth.exception.SessionCreationException;
import com.ivansario.secureauth.exception.TokenGenerationException;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.security.JwtUtil;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.RoleService;
import com.ivansario.secureauth.service.interfaces.UserRoleService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;
import com.ivansario.secureauth.util.RoleEnum;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    
    private final UserServiceImpl userService;
    private final RefreshTokenService refreshTokenService;
    private final UserSessionService userSessionService;
    private final RoleService roleService;
    private final UserRoleService userRoleService;

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {
        
        Authentication authentication;
        try {
            authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (AuthenticationException e) {
            log.warn("Intento de login fallido para usuario: {}", request.getUsername());
            throw new InvalidCredentialsException("Credenciales inválidas");
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userService.findUser(userDetails.getUsername());
        
        if (user == null) {
            log.error("Usuario no encontrado después de autenticación: {}", userDetails.getUsername());
            throw new UserNotFoundException("Usuario no encontrado: " + userDetails.getUsername());
        }

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(userDetails);
        } catch (Exception e) {
            log.error("Error generando access token para usuario: {}", user.getUsername(), e);
            throw new TokenGenerationException("No se pudo generar access token", e);
        }

        RefreshToken refreshToken = refreshTokenService.create(user, ipAddress, userAgent);
        if (refreshToken == null) {
            log.error("Fallo creando refresh token para usuario: {}", user.getUsername());
            throw new TokenGenerationException("No se pudo generar refresh token");
        }

        UserSession userSession = userSessionService.create(user, refreshToken, ipAddress, userAgent);
        if (userSession == null) {
            log.error("Fallo creando sesión para usuario: {}", user.getUsername());
            throw new SessionCreationException("No se pudo crear sesión de usuario");
        }

        user.setLastLogin(LocalDateTime.now());
        userService.updateUser(user);

        log.info("Usuario {} inició sesión exitosamente. IP: {}", user.getUsername(), ipAddress);

        return AuthResponse.builder()
            .username(user.getUsername())
            .email(user.getEmail())
            .accessToken(accessToken)
            .refreshToken(refreshToken.getToken())
            .build();
    }

    @Override
    public void logout(String refreshToken) {
        
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest, String ipAddress, String userAgent) {
        RefreshToken oldRefreshToken = refreshTokenService.findByToken(refreshTokenRequest.getRefreshToken());
        validateRefreshToken(oldRefreshToken);

        User user = oldRefreshToken.getUser();
        UserDetails userDetails = userService.loadUserByUsername(user.getUsername());

        RefreshToken updatedRefreshToken = refreshTokenService.update(oldRefreshToken);
        if (!updatedRefreshToken.isRevoked()) {
            log.error("El intento de revocación del token salió mal");
            throw new RefreshTokenExpiredException("El intento de revocación del token salió mal");
        }
        
        String newToken = jwtUtil.generateToken(userDetails);

        RefreshToken newRefreshToken = refreshTokenService.create(
            user, 
            ipAddress, 
            userAgent
        );
        validateCreatedEntity(newRefreshToken, "New Refresh token");

        UserSession userSession = userSessionService.create(
            user, 
            newRefreshToken, 
            ipAddress, 
            userAgent
        );
        validateCreatedEntity(userSession, "Sesión de usuario");

        log.info("RefreshToken ejecutado para usuario: {}. IP: {}", user.getUsername(), ipAddress);


        return AuthResponse.builder()
            .username(user.getUsername())
            .email(user.getEmail())
            .role(user.getRoles())
            .accessToken(newToken)
            .refreshToken(newRefreshToken.getToken())
            .build();
    }

    private void validateRefreshToken(RefreshToken refreshToken) {
        if (refreshToken == null) {
            log.error("Refresh token no válido");
            throw new InvalidRefreshTokenException("Refresh token no válido");
        }
        if (refreshToken.isExpired()) {
            log.error("Refresh token expirado");
            throw new RefreshTokenExpiredException("Refresh token expirado");
        }
        if (!refreshToken.getUser().getEnabled()) {
            log.error("Refresh token no válido");
            throw new UserNotFoundException("Usuario inactivo");
        }
    }

    @Override
    @Transactional
    public AuthResponse register(
        CreateUserRequest request, 
        String ipAddress, 
        String userAgent, 
        RoleEnum roleType
    ) {
        if (userService.existsUser(request.getEmail())) {
            throw new RuntimeException("Email ya registrado");
        }
        
        Role role = roleService.findByName(roleType);
        if (role == null) {
            log.error("Error: Rol no encontrado: " + roleType);
            throw new RuntimeException("Error: Rol no encontrado: " + roleType);
        }

        User user = userService.createUser(request, role);
        validateCreatedEntity(user, "Usuario");

        UserRole userRole = userRoleService.create(user, role);
        validateCreatedEntity(userRole, "Rol de usuario");

        user.setUserRoles(Set.of(userRole));
        String accessToken = jwtUtil.generateToken(user);

        RefreshToken refreshToken = refreshTokenService.create(user, ipAddress, userAgent);
        validateCreatedEntity(refreshToken, "Refresh token");
        
        UserSession userSession = userSessionService.create(user, refreshToken, ipAddress, userAgent);
        validateCreatedEntity(userSession, "Sesión de usuario");
        
        return AuthResponse.builder()
            .accessToken(accessToken)
            .email(user.getEmail())
            .username(user.getUsername())
            .refreshToken(refreshToken.getToken())
            .role(user.getRoles())
            .build();
    }

    private void validateCreatedEntity(Object entity, String entityName) {
        if (entity == null) {
            log.error("Error: {} no creado", entityName);
            throw new RuntimeException("Error: " + entityName + " no creado");
        }
    }

}
