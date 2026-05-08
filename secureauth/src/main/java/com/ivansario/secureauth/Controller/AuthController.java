package com.ivansario.secureauth.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.LogoutRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.util.RoleEnum;

import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@Controller
@RequiredArgsConstructor
@RequestMapping(path = "/api/auth/")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> postMethodName(
        @Valid @RequestBody 
        LoginRequest loginRequest, 
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        AuthResponse authresponse = authService.login(loginRequest, ipAddress, userAgent);
        return ResponseEntity.ok(authresponse);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> registerUser(
        @Valid @RequestBody 
        CreateUserRequest requestCreateUser,
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(
            authService.register(
                requestCreateUser, 
                ipAddress, 
                userAgent, 
                RoleEnum.ROLE_USER
            )
        );
    }

    @PostMapping("/registerAdmin")
    public ResponseEntity<AuthResponse> registerAdmin(
        @Valid @RequestBody 
        CreateUserRequest requestAdminCreate,
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(
            authService.register(
                requestAdminCreate, 
                ipAddress, 
                userAgent, 
                RoleEnum.ROLE_ADMIN
            )
        );
    }
    
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequest request) {
        authService.logout(request.getRefreshToken());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
        @Valid @RequestBody 
        RefreshTokenRequest refreshTokenRequest, 
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest, ipAddress, userAgent));
    }

}
