package com.ivansario.secureauth.service;

import java.time.LocalDateTime;

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
import com.ivansario.secureauth.security.JwtUtil;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.RoleService;
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
        .id(Long.valueOf(user.getId().toString()))
        .username(user.getUsername())
        .email(user.getEmail())
        .accessToken(accessToken)
        .refreshToken(refreshToken.getToken())
        .build();
    }

    @Override
    public AuthResponse register(CreateUserRequest request) {
        if (userService.existsUser(request.getEmail())) {
            throw new RuntimeException("Email ya registrado");
        }
        
        Role userRole = roleService.findByName(RoleEnum.USER);
        if (userRole == null) {
            log.error("Error: Rol no encontrado: " + RoleEnum.USER);
            throw new RuntimeException("Error: Rol no encontrado: " + RoleEnum.USER);
        }

        User user = userService.createUser(request, userRole);

        return AuthResponse.builder()
        .username(user.getUsername())
        .email(user.getEmail())
        .build();
    }

    @Override
    public void logout(String refreshToken) {
        
    }

    @Override
    public AuthResponse refreshToken(RefreshTokenRequest refreshTockenRequest, String ipAddress, String userAgent) {
        return null;
    }

}
