package com.ivansario.secureauth.service;

import java.time.LocalDateTime;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.dto.RegisterResponse;
import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.exception.InvalidConfirmationPasswordException;
import com.ivansario.secureauth.exception.InvalidCredentialsException;
import com.ivansario.secureauth.exception.InvalidRefreshTokenException;
import com.ivansario.secureauth.exception.RefreshTokenExpiredException;
import com.ivansario.secureauth.exception.SessionCreationException;
import com.ivansario.secureauth.exception.TokenGenerationException;
import com.ivansario.secureauth.exception.UserExistsException;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.security.JwtUtil;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.RoleService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;
import com.ivansario.secureauth.util.RoleEnum;

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

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    private final UserServiceImpl userService;
    private final RefreshTokenService refreshTokenService;
    private final UserSessionService userSessionService;
    private final RoleService roleService;

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

        Authentication authentication = authenticate(request.getUsername(), request.getPassword());

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userService.findUser(userDetails.getUsername());

        if (user == null) {
            throw new UserNotFoundException("User not found: " + userDetails.getUsername());
        }

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(userDetails);
        } catch (Exception e) {
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

        // Revocar refresh token
        refreshTokenService.revokeToken(foundRefreshToken);

        // Revocar sesión del usuario
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

    /**
    * Registers a new user with the specified role.
    *
    * @param request   data to create the user
    * @param ipAddress client IP address
    * @param userAgent client info (User-Agent)
    * @param roleType  role to assign to the user
    * @return {@link RegisterResponse} with created user info
     */
    @Override
    @Transactional
    public RegisterResponse register(
            CreateUserRequest request,
            String ipAddress,
            String userAgent,
            RoleEnum roleType) {

        if (userService.existsUser(request.getEmail())) {
            throw new UserExistsException("Email already registered");
        }

        Role role = roleService.findByName(roleType);
        if (role == null) {
            throw new RuntimeException("Error: Role not found: " + roleType);
        }

        User user = userService.createUser(request, role);
        validateCreatedEntity(user, "User");

        user.setRole(role);

        log.info("User {} registered successfully. Please log in to obtain access.", user.getUsername());

        return RegisterResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().getName().name())
                .build();
    }

    @Override
    @Transactional
    public AuthResponse changePassword(
            NewPasswordUserRequest request, 
            String ipAddress, 
            String userAgent) {

        String pass1 = request.getNewPassword();
        String pass2 = request.getConfirmPassword();

        if (!pass1.equals(pass2)) { 
            throw new InvalidConfirmationPasswordException("The provided passwords are not valid");
        }

        String token = request.getToken();

        RefreshToken refreshToken = refreshTokenService.findByToken(token);
        if (refreshToken == null || refreshToken.isExpired()) {
            throw new RefreshTokenExpiredException("Refresh token expired");
        }

        if (userService.existsUser(refreshToken.getUser().getEmail())) {
            throw new UserNotFoundException("Email already registered");
        }

        User userNewPassword = userService.changePassword(refreshToken.getUser(), pass1);
        validateCreatedEntity(userNewPassword, "User");

        Authentication authentication = authenticate(userNewPassword.getUsername(), userNewPassword.getPassword());

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(userDetails);
        } catch (Exception e) {
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
     * Realiza la autenticación usando el {@code AuthenticationManager}.
     */
    private Authentication authenticate(String username, String password) {
        try {
            return authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
        } catch (AuthenticationException e) {
            try {
                User user = userService.findUser(username);
                return authManager.authenticate(
                        new UsernamePasswordAuthenticationToken(user.getEmail(), password));
            } catch (Exception fallbackException) {
                throw new InvalidCredentialsException("Invalid credentials");
            }
        }
    }

    /**
     * Valida que una entidad creada no sea nula; lanza RuntimeException en caso
     * contrario.
     */
    private void validateCreatedEntity(Object entity, String entityName) {
        if (entity == null) {
            throw new RuntimeException("Error: " + entityName + " not created");
        }
    }

    /**
     * Valida la existencia y estado del refresh token.
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
     * Crea o actualiza el refresh token y sincroniza la sesión del usuario.
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
     * Crea o actualiza la sesión de usuario con el token y metadatos actuales.
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
     * Resuelve los detalles de usuario necesarios para generar tokens.
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
