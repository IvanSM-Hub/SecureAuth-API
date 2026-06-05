package com.ivansario.secureauth.service.interfaces;

import com.ivansario.secureauth.dto.auth.AuthResponse;
import com.ivansario.secureauth.dto.auth.InitialAdminLoginRequest;
import com.ivansario.secureauth.dto.auth.LoginRequest;
import com.ivansario.secureauth.dto.auth.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.auth.RefreshTokenRequest;

/**
 * Authentication service contract for login, token lifecycle, and password updates.
 */
public interface AuthService {

    /**
     * Authenticates a user and returns access and refresh tokens.
     *
     * @param request login request payload
     * @param ipAddress client IP address
     * @param userAgent client user-agent string
     * @return authentication response with generated tokens
     */
    AuthResponse login(LoginRequest request, String ipAddress, String userAgent);

    /**
     * Authenticates the bootstrap admin account.
     *
     * @param request initial admin login payload
     * @param ipAddress client IP address
     * @param userAgent client user-agent string
     * @return authentication response with generated tokens
     */
    AuthResponse initialAdminLogin(InitialAdminLoginRequest request, String ipAddress, String userAgent);

    /**
     * Rotates access and refresh tokens using a valid refresh token.
     *
     * @param refreshTokenRequest refresh token payload
     * @param ipAddress client IP address
     * @param userAgent client user-agent string
     * @return authentication response with refreshed tokens
     */
    AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest, String ipAddress, String userAgent);

    /**
     * Logs out the user by revoking the provided refresh token.
     *
     * @param logoutRefreshToken refresh token payload used for logout
     */
    void logout(RefreshTokenRequest logoutRefreshToken);

    /**
     * Changes the user password and issues a new token pair.
     *
     * @param request password change payload
     * @param ipAddress client IP address
     * @param userAgent client user-agent string
     * @return authentication response with refreshed credentials
     */
    AuthResponse changePassword(NewPasswordUserRequest request, String ipAddress, String userAgent);

}
