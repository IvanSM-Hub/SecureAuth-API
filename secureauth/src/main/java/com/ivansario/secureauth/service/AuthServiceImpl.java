package com.ivansario.secureauth.service;

import java.time.LocalDateTime;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
        
        String userKey = request.getUsername();
        String password = request.getPassword();

        authManager.authenticate(
            new UsernamePasswordAuthenticationToken(userKey, password)
        );

        User user;
        user = userService.findUser(userKey);

        String accessToken = jwtUtil.generateToken(userService.loadUserByUsername(user.getUsername()));

        RefreshToken refreshToken = refreshTokenService.create(user, ipAddress, userAgent);

        userSessionService.create(user, refreshToken, ipAddress, userAgent);

        user.setLastLogin(LocalDateTime.now());
        userService.updateUser(user);

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
    public AuthResponse refreshToken(RefreshTokenRequest refreshTockenRequest, String ipAddress, String userAgent) {
        return null;
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

        // Keep role authorities available in-memory for JWT generation.
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
        .role(roleType)
        .build();
    }

    private void validateCreatedEntity(Object entity, String entityName) {
        if (entity == null) {
            log.error("Error: {} no creado", entityName);
            throw new RuntimeException("Error: " + entityName + " no creado");
        }
    }

}
