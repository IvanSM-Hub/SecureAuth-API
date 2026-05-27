package com.ivansario.secureauth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

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
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.security.JwtUtil;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.RoleService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;
import com.ivansario.secureauth.util.RoleEnum;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthServiceImplTest {

    @Mock
    private AuthenticationManager authManager;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private UserServiceImpl userService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private UserSessionService userSessionService;

    @Mock
    private RoleService roleService;

    @Mock
    private Authentication authentication;

    @Mock
    private UserDetails userDetails;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthServiceImpl authService;

    private User user;
    private Role roleAdmin;
    private Role roleUser;
    private RefreshToken refreshToken;
    private UserSession userSession;

    private final String username = "testuser";
    private final String email = "test@email.com";
    private final String password = "password123";
    private final String passwordHash = "hashed_password";
    private final String accessToken = "access_token_jwt";
    private final String refreshTokenValue = "refresh_token_uuid";
    private final String ipAddress = "192.168.1.1";
    private final String userAgent = "Mozilla/5.0...";

    @BeforeEach
    void setUp() {
        user = User.builder()
            .username(username)
            .email(email)
            .passwordHash(passwordHash)
            .name("Test")
            .surname("User")
            .enabled(true)
            .build();
        user.setId(UUID.randomUUID());

        roleAdmin = Role.builder()
            .name(RoleEnum.ROLE_ADMIN)
            .description("Full system access")
            .build();
        roleAdmin.setId(UUID.randomUUID());

        roleUser = Role.builder()
            .name(RoleEnum.ROLE_USER)
            .description("Standard user")
            .build();
        roleUser.setId(UUID.randomUUID());

        user.setRole(roleUser);

        refreshToken = RefreshToken.builder()
            .token(refreshTokenValue)
            .user(user)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .revoked(false)
            .expiryDate(LocalDateTime.now().plusDays(7))
            .build();
        refreshToken.setId(UUID.randomUUID());

        userSession = UserSession.builder()
            .user(user)
            .refreshToken(refreshToken)
            .ipAddress(ipAddress)
            .deviceInfo(userAgent)
            .createdAt(LocalDateTime.now())
            .lastActivity(LocalDateTime.now())
            .revoked(false)
            .build();
        userSession.setId(UUID.randomUUID());

        when(userDetails.getUsername()).thenReturn(username);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userService.findUser(email)).thenReturn(user);
    }

    @Nested
    class LoginTests {

        @Test
        void shouldLoginSuccessfully() {
            LoginRequest loginRequest = new LoginRequest(username, password);

            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
            when(userService.findUser(username)).thenReturn(user);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);
            when(refreshTokenService.existsRefreshTokenByUser(user)).thenReturn(false);
            when(refreshTokenService.create(user, ipAddress, userAgent)).thenReturn(refreshToken);
            when(userSessionService.findByUser(user)).thenReturn(null);
            when(userService.updateUser(any(User.class))).thenReturn(user);

            AuthResponse response = authService.login(loginRequest, ipAddress, userAgent);

            assertNotNull(response);
            assertEquals(username, response.getUsername());
            assertEquals(email, response.getEmail());
            assertEquals(accessToken, response.getAccessToken());
            assertEquals(refreshTokenValue, response.getRefreshToken());
            verify(authManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
            verify(jwtUtil).generateToken(userDetails);
            verify(userService).updateUser(any(User.class));
        }

        @Test
        void shouldLoginWithExistingRefreshToken() {
            LoginRequest loginRequest = new LoginRequest(username, password);

            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
            when(userService.findUser(username)).thenReturn(user);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);
            when(refreshTokenService.existsRefreshTokenByUser(user)).thenReturn(true);
            when(refreshTokenService.findByUser(user)).thenReturn(refreshToken);
            when(refreshTokenService.updateToken(refreshToken, ipAddress, userAgent)).thenReturn(refreshToken);
            when(userSessionService.findByUser(user)).thenReturn(userSession);
            when(userService.updateUser(any(User.class))).thenReturn(user);

            AuthResponse response = authService.login(loginRequest, ipAddress, userAgent);

            assertNotNull(response);
            assertEquals(accessToken, response.getAccessToken());
            verify(refreshTokenService).updateToken(refreshToken, ipAddress, userAgent);
        }

        @Test
        void shouldThrowInvalidCredentialsExceptionOnAuthenticationFailure() {
            LoginRequest loginRequest = new LoginRequest(username, password);

            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new AuthenticationException("Invalid credentials") {});
            when(userService.findUser(username)).thenThrow(new RuntimeException("User not found"));

            assertThrows(InvalidCredentialsException.class, 
                () -> authService.login(loginRequest, ipAddress, userAgent));
        }

        @Test
        void shouldThrowUserNotFoundExceptionWhenUserDoesNotExist() {
            LoginRequest loginRequest = new LoginRequest(username, password);

            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
            when(userService.findUser(username)).thenReturn(null);

            assertThrows(UserNotFoundException.class,
                () -> authService.login(loginRequest, ipAddress, userAgent));
        }

        @Test
        void shouldThrowTokenGenerationExceptionOnJwtError() {
            LoginRequest loginRequest = new LoginRequest(username, password);

            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
            when(userService.findUser(username)).thenReturn(user);
            when(jwtUtil.generateToken(userDetails)).thenThrow(new RuntimeException("JWT error"));

            assertThrows(TokenGenerationException.class,
                () -> authService.login(loginRequest, ipAddress, userAgent));
        }

        @Test
        void shouldUpdateUserLastLoginTime() {
            LoginRequest loginRequest = new LoginRequest(username, password);
            LocalDateTime beforeLogin = LocalDateTime.now();

            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
            when(userService.findUser(username)).thenReturn(user);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);
            when(refreshTokenService.existsRefreshTokenByUser(user)).thenReturn(false);
            when(refreshTokenService.create(user, ipAddress, userAgent)).thenReturn(refreshToken);
            when(userSessionService.findByUser(user)).thenReturn(null);
            when(userService.updateUser(any(User.class))).thenReturn(user);

            authService.login(loginRequest, ipAddress, userAgent);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userService).updateUser(userCaptor.capture());
            User updatedUser = userCaptor.getValue();
            assertThat(updatedUser.getLastLogin()).isAfterOrEqualTo(beforeLogin);
        }
    }

    @Nested
    class LogoutTests {

        @Test
        void shouldLogoutSuccessfully() {
            RefreshTokenRequest logoutRequest = new RefreshTokenRequest(refreshTokenValue);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);

            authService.logout(logoutRequest);

            verify(refreshTokenService).revokeToken(refreshToken);
            verify(userSessionService).revokeSession(user);
        }

        @Test
        void shouldThrowInvalidRefreshTokenExceptionWhenTokenNotFound() {
            RefreshTokenRequest logoutRequest = new RefreshTokenRequest(refreshTokenValue);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(null);

            assertThrows(InvalidRefreshTokenException.class,
                () -> authService.logout(logoutRequest));
        }

        @Test
        void shouldThrowRefreshTokenExpiredExceptionWhenTokenIsExpired() {
            RefreshTokenRequest logoutRequest = new RefreshTokenRequest(refreshTokenValue);
            refreshToken.setExpiryDate(LocalDateTime.now().minusDays(1));

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);

            assertThrows(RefreshTokenExpiredException.class,
                () -> authService.logout(logoutRequest));
        }

        @Test
        void shouldNotRevokeSessionIfTokenIsInvalid() {
            RefreshTokenRequest logoutRequest = new RefreshTokenRequest(refreshTokenValue);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(null);

            assertThrows(InvalidRefreshTokenException.class,
                () -> authService.logout(logoutRequest));
            verify(userSessionService, never()).revokeSession(any(User.class));
        }

        @Test
        void shouldThrowUserNotFoundExceptionWhenUserIsDisabled() {
            RefreshTokenRequest logoutRequest = new RefreshTokenRequest(refreshTokenValue);
            user.setEnabled(false);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);

            assertThrows(UserNotFoundException.class,
                () -> authService.logout(logoutRequest));
        }
    }

    @Nested
    class RefreshTokenTests {

        @Test
        void shouldRefreshTokenSuccessfully() {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshTokenValue);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(userService.loadUserByUsername(email)).thenReturn(userDetails);
            when(userSessionService.findByUser(user)).thenReturn(userSession);
            when(refreshTokenService.updateToken(refreshToken, ipAddress, userAgent))
                .thenReturn(refreshToken);
            when(refreshTokenService.create(user, ipAddress, userAgent)).thenReturn(refreshToken);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);

            AuthResponse response = authService.refreshToken(refreshRequest, ipAddress, userAgent);

            assertNotNull(response);
            assertEquals(username, response.getUsername());
            assertEquals(email, response.getEmail());
            assertEquals(accessToken, response.getAccessToken());
            verify(userSessionService).update(any(UserSession.class));
        }

        @Test
        void shouldThrowInvalidRefreshTokenExceptionWhenTokenNotFound() {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshTokenValue);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(null);

            assertThrows(InvalidRefreshTokenException.class,
                () -> authService.refreshToken(refreshRequest, ipAddress, userAgent));
        }

        @Test
        void shouldThrowRefreshTokenExpiredExceptionWhenTokenIsExpired() {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshTokenValue);
            refreshToken.setExpiryDate(LocalDateTime.now().minusDays(1));

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);

            assertThrows(RefreshTokenExpiredException.class,
                () -> authService.refreshToken(refreshRequest, ipAddress, userAgent));
        }

        @Test
        void shouldThrowSessionCreationExceptionWhenTokenIsRevoked() {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshTokenValue);
            refreshToken.setRevoked(true);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);

            assertThrows(SessionCreationException.class,
                () -> authService.refreshToken(refreshRequest, ipAddress, userAgent));
        }

        @Test
        void shouldRefreshTokenWhenSessionIsRevoked() {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshTokenValue);
            UserSession revokedSession = UserSession.builder()
                .user(user)
                .refreshToken(refreshToken)
                .revoked(true)
                .build();

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(userService.loadUserByUsername(email)).thenReturn(userDetails);
            when(userSessionService.findByUser(user)).thenReturn(revokedSession);
            when(refreshTokenService.existsRefreshTokenByUser(user)).thenReturn(false);
            when(refreshTokenService.create(user, ipAddress, userAgent)).thenReturn(refreshToken);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);

            AuthResponse response = authService.refreshToken(refreshRequest, ipAddress, userAgent);

            assertNotNull(response);
            assertEquals(accessToken, response.getAccessToken());
            verify(userSessionService).update(any(UserSession.class));
        }

        @Test
        void shouldCreateSessionWhenSessionDoesNotExist() {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshTokenValue);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(userService.loadUserByUsername(email)).thenReturn(userDetails);
            when(userSessionService.findByUser(user)).thenReturn(null);
            when(refreshTokenService.existsRefreshTokenByUser(user)).thenReturn(false);
            when(refreshTokenService.create(user, ipAddress, userAgent)).thenReturn(refreshToken);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);

            AuthResponse response = authService.refreshToken(refreshRequest, ipAddress, userAgent);

            assertNotNull(response);
            assertEquals(accessToken, response.getAccessToken());
            verify(userSessionService).create(user, refreshToken, ipAddress, userAgent);
        }

        @Test
        void shouldUpdateSessionWithNewTokenData() {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshTokenValue);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(userService.loadUserByUsername(email)).thenReturn(userDetails);
            when(userSessionService.findByUser(user)).thenReturn(userSession);
            when(refreshTokenService.existsRefreshTokenByUser(user)).thenReturn(true);
            when(refreshTokenService.findByUser(user)).thenReturn(refreshToken);
            when(refreshTokenService.updateToken(refreshToken, ipAddress, userAgent)).thenReturn(refreshToken);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);

            authService.refreshToken(refreshRequest, ipAddress, userAgent);

            ArgumentCaptor<UserSession> sessionCaptor = ArgumentCaptor.forClass(UserSession.class);
            verify(userSessionService).update(sessionCaptor.capture());
            UserSession updatedSession = sessionCaptor.getValue();
            assertEquals(refreshToken, updatedSession.getRefreshToken());
            assertEquals(ipAddress, updatedSession.getIpAddress());
            assertEquals(userAgent, updatedSession.getDeviceInfo());
        }
    }

    @Nested
    class RegisterTests {

        @Test
        void shouldRegisterUserSuccessfully() {
            CreateUserRequest registerRequest = CreateUserRequest.builder()
                .email(email)
                .username(username)
                .password(password)
                .build();

            user.setRole(roleUser);
            when(userService.existsUser(email)).thenReturn(false);
            when(roleService.findByName(RoleEnum.ROLE_USER)).thenReturn(roleUser);
            when(userService.createUser(registerRequest, roleUser)).thenReturn(user);

            RegisterResponse response = authService.register(registerRequest, ipAddress, userAgent, RoleEnum.ROLE_USER);

            assertNotNull(response);
            assertEquals(username, response.getUsername());
            assertEquals(email, response.getEmail());
            verify(userService).createUser(registerRequest, roleUser);
        }

        @Test
        void shouldThrowExceptionWhenEmailAlreadyExists() {
            CreateUserRequest registerRequest = CreateUserRequest.builder()
                .email(email)
                .username(username)
                .password(password)
                .build();

            when(userService.existsUser(email)).thenReturn(true);

            assertThrows(RuntimeException.class,
                () -> authService.register(registerRequest, ipAddress, userAgent, RoleEnum.ROLE_USER));
            verify(userService, never()).createUser(any(CreateUserRequest.class), any(Role.class));
        }

        @Test
        void shouldThrowExceptionWhenRoleNotFound() {
            CreateUserRequest registerRequest = CreateUserRequest.builder()
                .email(email)
                .username(username)
                .password(password)
                .build();

            when(userService.existsUser(email)).thenReturn(false);
            when(roleService.findByName(RoleEnum.ROLE_ADMIN)).thenReturn(null);

            assertThrows(RuntimeException.class,
                () -> authService.register(registerRequest, ipAddress, userAgent, RoleEnum.ROLE_ADMIN));
        }

        @Test
        void shouldThrowExceptionWhenUserCreationFails() {
            CreateUserRequest registerRequest = CreateUserRequest.builder()
                .email(email)
                .username(username)
                .password(password)
                .build();

            when(userService.existsUser(email)).thenReturn(false);
            when(roleService.findByName(RoleEnum.ROLE_USER)).thenReturn(roleUser);
            when(userService.createUser(registerRequest, roleUser)).thenReturn(null);

            assertThrows(RuntimeException.class,
                () -> authService.register(registerRequest, ipAddress, userAgent, RoleEnum.ROLE_USER));
        }

        @Test
        void shouldAssignCorrectRoleToNewUser() {
            CreateUserRequest registerRequest = CreateUserRequest.builder()
                .email(email)
                .username(username)
                .password(password)
                .build();

            user.setRole(roleAdmin);
            when(userService.existsUser(email)).thenReturn(false);
            when(roleService.findByName(RoleEnum.ROLE_ADMIN)).thenReturn(roleAdmin);
            when(userService.createUser(registerRequest, roleAdmin)).thenReturn(user);

            RegisterResponse response = authService.register(registerRequest, ipAddress, userAgent, RoleEnum.ROLE_ADMIN);

            assertNotNull(response);
            assertEquals(RoleEnum.ROLE_ADMIN.name(), response.getRole());
        }
    }

    @Nested
    class ChangePasswordTests {

        @Test
        void shouldChangePasswordSuccessfully() {
            String newPassword = "newPassword123";
            String confirmPassword = "newPassword123";
            NewPasswordUserRequest changeRequest = new NewPasswordUserRequest(refreshTokenValue, password, newPassword, confirmPassword);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(passwordEncoder.matches(password, passwordHash)).thenReturn(true);
            when(userService.changePassword(user, newPassword)).thenReturn(user);
            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);
            when(refreshTokenService.existsRefreshTokenByUser(user)).thenReturn(true);
            when(refreshTokenService.findByUser(user)).thenReturn(refreshToken);
            when(refreshTokenService.updateToken(refreshToken, ipAddress, userAgent))
                .thenReturn(refreshToken);
            when(userSessionService.findByUser(user)).thenReturn(userSession);

            AuthResponse response = authService.changePassword(changeRequest, ipAddress, userAgent);

            assertNotNull(response);
            assertEquals(username, response.getUsername());
            verify(userService).changePassword(user, newPassword);
            verify(refreshTokenService).findByToken(refreshTokenValue);
        }

        @Test
        void shouldThrowInvalidConfirmationPasswordExceptionWhenPasswordsDoNotMatch() {
            String newPassword = "newPassword123";
            String confirmPassword = "differentPassword123";
            NewPasswordUserRequest changeRequest = new NewPasswordUserRequest(refreshTokenValue, password, newPassword, confirmPassword);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(passwordEncoder.matches(password, passwordHash)).thenReturn(true);

            assertThrows(InvalidConfirmationPasswordException.class,
                () -> authService.changePassword(changeRequest, ipAddress, userAgent));
            verify(userService, never()).changePassword(any(User.class), anyString());
        }

        @Test
        void shouldThrowRefreshTokenExpiredExceptionWhenTokenIsExpired() {
            String newPassword = "newPassword123";
            String confirmPassword = "newPassword123";
            NewPasswordUserRequest changeRequest = new NewPasswordUserRequest(refreshTokenValue, password, newPassword, confirmPassword);
            refreshToken.setExpiryDate(LocalDateTime.now().minusDays(1));

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);

            assertThrows(RefreshTokenExpiredException.class,
                () -> authService.changePassword(changeRequest, ipAddress, userAgent));
        }

        @Test
        void shouldThrowRefreshTokenExpiredExceptionWhenTokenIsNull() {
            String newPassword = "newPassword123";
            String confirmPassword = "newPassword123";
            NewPasswordUserRequest changeRequest = new NewPasswordUserRequest(refreshTokenValue, password, newPassword, confirmPassword);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(null);

            assertThrows(RefreshTokenExpiredException.class,
                () -> authService.changePassword(changeRequest, ipAddress, userAgent));
        }

        @Test
        void shouldThrowInvalidCredentialsExceptionWhenAuthenticationFails() {
            String newPassword = "newPassword123";
            String confirmPassword = "newPassword123";
            NewPasswordUserRequest changeRequest = new NewPasswordUserRequest(refreshTokenValue, password, newPassword, confirmPassword);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(passwordEncoder.matches(password, passwordHash)).thenReturn(true);
            when(userService.changePassword(user, newPassword)).thenReturn(user);
            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new AuthenticationException("Auth failed") {});

            assertThrows(InvalidCredentialsException.class,
                () -> authService.changePassword(changeRequest, ipAddress, userAgent));
        }

        @Test
        void shouldThrowTokenGenerationExceptionOnJwtError() {
            String newPassword = "newPassword123";
            String confirmPassword = "newPassword123";
            NewPasswordUserRequest changeRequest = new NewPasswordUserRequest(refreshTokenValue, password, newPassword, confirmPassword);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(passwordEncoder.matches(password, passwordHash)).thenReturn(true);
            when(userService.changePassword(user, newPassword)).thenReturn(user);
            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
            when(jwtUtil.generateToken(userDetails)).thenThrow(new RuntimeException("JWT error"));

            assertThrows(TokenGenerationException.class,
                () -> authService.changePassword(changeRequest, ipAddress, userAgent));
        }

        @Test
        void shouldReturnValidTokensAfterPasswordChange() {
            String newPassword = "newPassword123";
            String confirmPassword = "newPassword123";
            NewPasswordUserRequest changeRequest = new NewPasswordUserRequest(refreshTokenValue, password, newPassword, confirmPassword);

            when(refreshTokenService.findByToken(refreshTokenValue)).thenReturn(refreshToken);
            when(passwordEncoder.matches(password, passwordHash)).thenReturn(true);
            when(userService.changePassword(user, newPassword)).thenReturn(user);
            when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
            when(jwtUtil.generateToken(userDetails)).thenReturn(accessToken);
            when(refreshTokenService.existsRefreshTokenByUser(user)).thenReturn(false);
            when(refreshTokenService.create(user, ipAddress, userAgent)).thenReturn(refreshToken);
            when(userSessionService.findByUser(user)).thenReturn(null);

            AuthResponse response = authService.changePassword(changeRequest, ipAddress, userAgent);

            assertNotNull(response.getAccessToken());
            assertNotNull(response.getRefreshToken());
            assertEquals(accessToken, response.getAccessToken());
            assertEquals(refreshTokenValue, response.getRefreshToken());
        }
    }
}
