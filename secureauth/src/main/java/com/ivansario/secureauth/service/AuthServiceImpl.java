package com.ivansario.secureauth.service;

import java.time.LocalDateTime;

import org.hibernate.validator.internal.constraintvalidators.bv.EmailValidator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.auth.AuthResponse;
import com.ivansario.secureauth.dto.auth.InitialAdminLoginRequest;
import com.ivansario.secureauth.dto.auth.LoginRequest;
import com.ivansario.secureauth.dto.auth.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.auth.RefreshTokenRequest;
import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.exception.InvalidConfirmationPasswordException;
import com.ivansario.secureauth.exception.InvalidCredentialsException;
import com.ivansario.secureauth.exception.InvalidRefreshTokenException;
import com.ivansario.secureauth.exception.RefreshTokenExpiredException;
import com.ivansario.secureauth.exception.SessionCreationException;
import com.ivansario.secureauth.exception.TokenGenerationException;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.exception.UserProtectionException;
import com.ivansario.secureauth.security.JwtUtil;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.UserProtectionService;
import com.ivansario.secureauth.service.interfaces.UserService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;

import jakarta.transaction.Transactional;

/**
 * Authentication service implementation.
 *
 * Provides login, logout, refresh token and user registration operations.
*/
@Service
@Slf4j
@Validated
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final UserSessionService userSessionService;
    private final UserProtectionService userProtectionService;

    private String ADMIN_EMAIL = "admin@admin.com";
    private String ADMIN_USERNAME = "admin";

    
    @Override
    public AuthResponse initialAdminLogin(InitialAdminLoginRequest request, String ipAddress, String userAgent) {
        if (validateAdminUsername(request.getUsername())) {
            throw new UserProtectionException("The user may be admin");
        }
        LoginRequest loginRequest = LoginRequest.builder()
        .username(request.getUsername())
        .password(request.getPassword())
        .build();

        return login(loginRequest, ipAddress, userAgent);
    }

    /**
    * Authenticates the user and generates access and refresh tokens, and
    * creates/updates the user's session.
    *
    * @param request   login data (username, password)
    * @param ipAddress client IP address
    * @param userAgent client info (User-Agent)
    * @return {@link AuthResponse} with tokens and user data
     */
    @Override
    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {

        boolean isBlockedUser = userProtectionService.isBlocked(request.getUsername(), ipAddress);
        if (isBlockedUser) {
            throw new UserProtectionException("The user provided is blocked");
        }

        Authentication authentication;
        try {
            authentication = authenticate(request.getUsername(), request.getPassword());
        } catch (AuthenticationException e) {
            userProtectionService.registerFailedAttempt(request.getUsername(), ipAddress);
            throw new InvalidCredentialsException("Invalid credentials", e);
        }

        userProtectionService.registerSuccessfulLogin(request.getUsername(), ipAddress);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userService.findUser(userDetails.getUsername());

        if (user == null) {
            throw new UserNotFoundException("User not found: " + userDetails.getUsername());
        }

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(userDetails);
        } catch (RuntimeException e) {
            throw new TokenGenerationException("Failed to generate access token", e);
        }

        RefreshToken refreshedToken = createOrUpdateRefreshTokenAndSession(user, ipAddress, userAgent);

        user.setLastLogin(LocalDateTime.now());
        User userNewLastLogin = userService.updateUser(user);
        validateCreatedEntity(userNewLastLogin, "User");

        log.info("User {} logged in successfully. IP: {}", userNewLastLogin.getUsername(), ipAddress);

        return AuthResponse.builder()
                .username(userNewLastLogin.getUsername())
                .email(userNewLastLogin.getEmail())
                .role(userNewLastLogin.getRole().getName().name())
                .accessToken(accessToken)
                .refreshToken(refreshedToken.getToken())
                .build();
    }

    /**
    * Closes the session associated with the provided refresh token and revokes it.
    *
    * @param logoutRefreshToken request containing the refresh token to revoke
     */
    @Override
    @Transactional
    public void logout(RefreshTokenRequest logoutRefreshToken) {
        
        RefreshToken foundRefreshToken = refreshTokenService.findByToken(logoutRefreshToken.getToken());
        validateRefreshToken(foundRefreshToken);

        User user = foundRefreshToken.getUser();

        // Revoke refresh token.
        refreshTokenService.revokeToken(foundRefreshToken);

        // Revoke active user session.
        userSessionService.revokeSession(user);

        log.info("User {} logged out successfully", user.getUsername());
    }

    /**
    * Renews tokens (access and refresh) using a valid refresh token.
    *
    * @param refreshTokenRequest request containing the current refresh token
    * @param ipAddress           client IP address
    * @param userAgent           client info (User-Agent)
    * @return {@link AuthResponse} with new tokens
     */
    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request, String ipAddress, String userAgent) {
        
        RefreshToken oldToken = refreshTokenService.findByToken(request.getToken());
        validateRefreshToken(oldToken);
        if (oldToken.isRevoked()) {
            throw new SessionCreationException("The user's token has been revoked");
        }

        User user = oldToken.getUser();

        UserSession userSession = userSessionService.findByUser(user);
        if (userSession == null || userSession.isRevoked()) {
            userSession = new UserSession();
        }
        UserDetails userDetails = resolveUserDetails(user);

        RefreshToken newToken = createOrUpdateRefreshTokenAndSession(user, ipAddress, userAgent);

        String newAccessToken = jwtUtil.generateToken(userDetails);

        log.info("Refresh token executed for user: {}. IP: {}", user.getUsername(), ipAddress);

        return AuthResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole() != null ? user.getRole().getName().name() : null)
                .accessToken(newAccessToken)
                .refreshToken(newToken.getToken())
                .build();
    }

    @Override
    @Transactional
    public AuthResponse changePassword(
        NewPasswordUserRequest request, 
        String ipAddress, 
        String userAgent
    ) {

        String token = request.getToken();
        String currentPass = request.getCurrentPassword();
        String newPass = request.getNewPassword();
        String confirmPass = request.getConfirmPassword();

        RefreshToken refreshToken = refreshTokenService.findByToken(token);
        if (refreshToken == null || refreshToken.isExpired() || refreshToken.isRevoked()) {
            throw new RefreshTokenExpiredException("Refresh token not exists or it's expired or has been revoked");
        }

        User user = userService.findUser(refreshToken.getUser().getEmail());
        if (!user.isEnabled()) {
            throw new UserNotFoundException("User not found: " + refreshToken.getUser().getEmail());
        }

        if (!passwordEncoder.matches(currentPass, user.getPassword())) {
            throw new InvalidConfirmationPasswordException("The current password is not valid");
        }
        if (!newPass.equals(confirmPass)) {
            throw new InvalidConfirmationPasswordException("The provided passwords are not valid");
        }

        User userNewPassword = userService.changePassword(user, newPass);
        Authentication authentication;
        try {
            authentication = authenticate(userNewPassword.getUsername(), newPass);
        } catch (AuthenticationException e) {
            throw new InvalidCredentialsException("Invalid credentials", e);
        }

        UserDetails newUserDetails = (UserDetails) authentication.getPrincipal();

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(newUserDetails);
        } catch (RuntimeException e) {
            throw new TokenGenerationException("Failed to generate access token", e);
        }

        RefreshToken refreshedToken = createOrUpdateRefreshTokenAndSession(userNewPassword, ipAddress, userAgent);

        log.info("Password changed successfully for {}. Please log in to obtain access.", userNewPassword.getUsername());


        return AuthResponse.builder()
                .username(userNewPassword.getUsername())
                .email(userNewPassword.getEmail())
                .role(userNewPassword.getRole().getName().name())
                .accessToken(accessToken)
                .refreshToken(refreshedToken.getToken())
                .build();
    }

    /**
     * Checks whether the provided credential matches the reserved admin identity.
     *
     * @param username username or email provided at login
     * @return {@code true} when the value matches the bootstrap admin account
     */
    private boolean validateAdminUsername(String username) {
        EmailValidator emailValidator = new EmailValidator();
        boolean isvalid = (emailValidator.isValid(username, null)) 
            ? ADMIN_EMAIL.equals(username) 
            : ADMIN_USERNAME.equalsIgnoreCase(username); 
        return !isvalid;
    }

    /**
     * Authenticates credentials using the configured {@code AuthenticationManager}.
     * It accepts either username or email in the same input field.
     *
     * @param username username or email used for authentication
     * @param password raw password
     * @return authenticated security context
     */
    private Authentication authenticate(String username, String password) {
        String normalizedUsername = username == null ? null : username.trim();
        return authManager.authenticate(
                new UsernamePasswordAuthenticationToken(normalizedUsername, password));
    }

    /**
     * Validates that a newly persisted entity is not null.
     *
     * @param entity persisted entity reference
     * @param entityName entity label for error messages
     */
    private void validateCreatedEntity(Object entity, String entityName) {
        if (entity == null) {
            throw new IllegalStateException(entityName + " was not created");
        }
    }

    /**
     * Validates refresh token existence and status.
     *
     * @param refreshToken token instance to validate
     */
    private void validateRefreshToken(RefreshToken refreshToken) {
        if (refreshToken == null) {
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }
        if (refreshToken.isExpired()) {
            throw new RefreshTokenExpiredException("Refresh token expired");
        }
        if (!refreshToken.getUser().getEnabled()) {
            throw new UserNotFoundException("User inactive");
        }
    }

    /**
     * Creates or rotates a refresh token and keeps user session metadata in sync.
     *
     * @param user token owner
     * @param ipAddress source IP address
     * @param userAgent client user-agent
     * @return active refresh token for the user
     */
    private RefreshToken createOrUpdateRefreshTokenAndSession(User user, String ipAddress, String userAgent) {
        RefreshToken refreshedToken;
        if (refreshTokenService.existsRefreshTokenByUser(user)) {
            refreshedToken = refreshTokenService.updateToken(refreshTokenService.findByUser(user), ipAddress, userAgent);
        } else {
            refreshedToken = refreshTokenService.create(user, ipAddress, userAgent);
        }
        validateRefreshToken(refreshedToken);

        upsertUserSession(user, refreshedToken, ipAddress, userAgent);
        return refreshedToken;
    }

    /**
     * Creates or updates the persisted user session with current token and metadata.
     *
     * @param user session owner
     * @param refreshToken active refresh token
     * @param ipAddress source IP address
     * @param userAgent client user-agent
     */
    private void upsertUserSession(User user, RefreshToken refreshToken, String ipAddress, String userAgent) {
        UserSession userSession = userSessionService.findByUser(user);
        if (userSession == null) {
            userSessionService.create(user, refreshToken, ipAddress, userAgent);
        } else {
            userSession.setRefreshToken(refreshToken);
            userSession.setIpAddress(ipAddress);
            userSession.setDeviceInfo(userAgent);
            userSession.setRevoked(false);
            userSessionService.update(userSession);
        }
    }

    /**
     * Resolves Spring Security user details required to generate JWT tokens.
     *
     * @param user authenticated domain user
     * @return user details for token generation
     */
    private UserDetails resolveUserDetails(User user) {
        try {
            return (UserDetails) userService.loadUserByUsername(user.getEmail());
        } catch (Exception emailException) {
                log.warn("Failed to load the user by email {}, trying by username {}", user.getEmail(),
                    user.getUsername());

            try {
                return (UserDetails) userService.findUser(user.getUsername());
            } catch (Exception usernameException) {
                throw new UserNotFoundException("User not found: " + user.getUsername());
            }
        }
    }

}
