package com.ivansario.secureauth.service.interfaces;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.dto.RegisterResponse;
import com.ivansario.secureauth.util.RoleEnum;

public interface AuthService {

    RegisterResponse register(CreateUserRequest request, String ipAddress, String userAgent, RoleEnum roleEnum);
    AuthResponse login(LoginRequest request, String ipAddress, String userAgent);
    AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest, String ipAddress, String userAgent);
    void logout(RefreshTokenRequest logoutRefreshToken);
    AuthResponse changePassword(NewPasswordUserRequest request, String ipAddress, String userAgent);

}
