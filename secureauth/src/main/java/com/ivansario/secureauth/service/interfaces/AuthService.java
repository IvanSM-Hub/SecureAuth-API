package com.ivansario.secureauth.service.interfaces;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;

public interface AuthService {

    AuthResponse register(CreateUserRequest request);
    AuthResponse login(LoginRequest request, String ipAddress, String userAgent);
    AuthResponse refreshToken(RefreshTokenRequest refreshTockenRequest, String ipAddress, String userAgent);
    void logout(String refreshToken);

}
