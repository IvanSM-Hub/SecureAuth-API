package com.ivansario.secureauth.service.interfaces;

import com.ivansario.secureauth.dto.auth.AuthResponse;
import com.ivansario.secureauth.dto.auth.InitialAdminLoginRequest;
import com.ivansario.secureauth.dto.auth.LoginRequest;
import com.ivansario.secureauth.dto.auth.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.auth.RefreshTokenRequest;
import com.ivansario.secureauth.dto.user.CreateUserRequest;
import com.ivansario.secureauth.dto.user.RegisterResponse;
import com.ivansario.secureauth.util.RoleEnum;

public interface AuthService {

    RegisterResponse register(CreateUserRequest request, String ipAddress, String userAgent, RoleEnum roleEnum);
    AuthResponse login(LoginRequest request, String ipAddress, String userAgent);
    AuthResponse initialAdminLogin(InitialAdminLoginRequest request, String ipAddress, String userAgent);
    AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest, String ipAddress, String userAgent);
    void logout(RefreshTokenRequest logoutRefreshToken);
    AuthResponse changePassword(NewPasswordUserRequest request, String ipAddress, String userAgent);

}
