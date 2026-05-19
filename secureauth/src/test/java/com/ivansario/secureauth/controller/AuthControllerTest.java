package com.ivansario.secureauth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
// import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ivansario.secureauth.Controller.AuthController;
import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.dto.RegisterResponse;
import com.ivansario.secureauth.security.JwtUtil;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.util.RoleEnum;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private JwtUtil jwtUtil;

    @MockitoBean
    private UserDetailsService userDetailsService;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private AuthService authService;

    private LoginRequest loginRequest;
    private CreateUserRequest registerRequest;
    private RefreshTokenRequest refreshTokenRequest;
    private NewPasswordUserRequest changePasswordRequest;
    private AuthResponse authResponse;
    private RegisterResponse registerResponse;

    private final String username = "testuser";
    private final String email = "test@email.com";
    private final String password = "password123";
    private final String accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private final String refreshToken = "550e8400-e29b-41d4-a716-446655440000";

    @BeforeEach
    void setUp() {
        loginRequest = new LoginRequest(username, password);

        registerRequest = CreateUserRequest.builder()
                .email(email)
                .username(username)
                .password(password)
                .build();

        refreshTokenRequest = new RefreshTokenRequest(refreshToken);

        changePasswordRequest = new NewPasswordUserRequest("newPassword123", "newPassword123", refreshToken);

        authResponse = AuthResponse.builder()
                .username(username)
                .email(email)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .role(Set.of("ROLE_USER"))
                .build();

        registerResponse = RegisterResponse.builder()
                .username(username)
                .email(email)
                .role(Set.of("ROLE_USER"))
                .build();
    }

    // @Test
    void shouldLoginSuccessfully() throws Exception {
        when(authService.login(any(LoginRequest.class), anyString(), anyString()))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.accessToken").value(accessToken))
                .andExpect(jsonPath("$.refreshToken").value(refreshToken))
                .andExpect(jsonPath("$.role[0]").value("ROLE_USER"));

        verify(authService).login(any(LoginRequest.class), anyString(), anyString());
    }

    // @Test
    void shouldLoginTestsVerifyAuthServiceIsCalledWithCorrectParameters() throws Exception {
        when(authService.login(any(LoginRequest.class), anyString(), anyString()))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        verify(authService).login(any(LoginRequest.class), anyString(), anyString());
    }

    // @Test
    void shouldLoginTestsReturnBadRequestWhenUsernameIsMissing() throws Exception {
        LoginRequest invalidRequest = new LoginRequest(null, password);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldLoginTestsReturnBadRequestWhenPasswordIsMissing() throws Exception {
        LoginRequest invalidRequest = new LoginRequest(username, null);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldLoginTestsReturnBadRequestWhenBodyIsEmpty() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldRegisterUserSuccessfully() throws Exception {
        when(authService.register(any(CreateUserRequest.class), anyString(), anyString(), eq(RoleEnum.ROLE_USER)))
                .thenReturn(registerResponse);

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role[0]").value("ROLE_USER"));

        verify(authService).register(any(CreateUserRequest.class), anyString(), anyString(), eq(RoleEnum.ROLE_USER));
    }

    // @Test
    void shouldRegisterTestsVerifyAuthServiceIsCalledWithCorrectRole() throws Exception {
        when(authService.register(any(CreateUserRequest.class), anyString(), anyString(), eq(RoleEnum.ROLE_USER)))
                .thenReturn(registerResponse);

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        verify(authService).register(any(CreateUserRequest.class), anyString(), anyString(), eq(RoleEnum.ROLE_USER));
    }

    // @Test
    void shouldRegisterTestsReturnBadRequestWhenEmailIsMissing() throws Exception {
        CreateUserRequest invalidRequest = CreateUserRequest.builder()
                .username(username)
                .password(password)
                .build();

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldRegisterTestsReturnBadRequestWhenUsernameIsMissing() throws Exception {
        CreateUserRequest invalidRequest = CreateUserRequest.builder()
                .email(email)
                .password(password)
                .build();

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldRegisterTestsReturnBadRequestWhenPasswordIsMissing() throws Exception {
        CreateUserRequest invalidRequest = CreateUserRequest.builder()
                .email(email)
                .username(username)
                .build();

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldRegisterTestsReturnBadRequestWhenEmailFormatIsInvalid() throws Exception {
        CreateUserRequest invalidRequest = CreateUserRequest.builder()
                .email("invalid-email")
                .username(username)
                .password(password)
                .build();

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldRegisterTestsReturnBadRequestWhenPasswordIsTooShort() throws Exception {
        CreateUserRequest invalidRequest = CreateUserRequest.builder()
                .email(email)
                .username(username)
                .password("short")
                .build();

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldLogoutTestsLogoutSuccessfully() throws Exception {
        doNothing().when(authService).logout(any(RefreshTokenRequest.class));

        mockMvc.perform(post("/api/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isNoContent());

        verify(authService).logout(any(RefreshTokenRequest.class));
    }

    // @Test
    void shouldLogoutTestsVerifyAuthServiceLogoutIsCalled() throws Exception {
        doNothing().when(authService).logout(any(RefreshTokenRequest.class));

        mockMvc.perform(post("/api/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isNoContent());

        verify(authService).logout(any(RefreshTokenRequest.class));
    }

    // @Test
    void shouldLogoutTestsReturnBadRequestWhenTokenIsMissing() throws Exception {
        RefreshTokenRequest invalidRequest = new RefreshTokenRequest(null);

        mockMvc.perform(post("/api/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldLogoutTestsReturnBadRequestWhenBodyIsEmpty() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldRefreshTokenSuccessfully() throws Exception {
        when(authService.refreshToken(any(RefreshTokenRequest.class), anyString(), anyString()))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.accessToken").value(accessToken))
                .andExpect(jsonPath("$.refreshToken").value(refreshToken));

        verify(authService).refreshToken(any(RefreshTokenRequest.class), anyString(), anyString());
    }

    // @Test
    void shouldRefreshTokenTestsVerifyAuthServiceIsCalledOnRefresh() throws Exception {
        when(authService.refreshToken(any(RefreshTokenRequest.class), anyString(), anyString()))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isOk());

        verify(authService).refreshToken(any(RefreshTokenRequest.class), anyString(), anyString());
    }

    // @Test
    void shouldRefreshTokenTestsReturnBadRequestWhenTokenIsMissing() throws Exception {
        RefreshTokenRequest invalidRequest = new RefreshTokenRequest(null);

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldRefreshTokenTestsReturnBadRequestWhenBodyIsEmpty() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldChangePasswordSuccessfully() throws Exception {
        when(authService.changePassword(any(NewPasswordUserRequest.class), anyString(), anyString()))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/auth/newPassword")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(changePasswordRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());

        verify(authService).changePassword(any(NewPasswordUserRequest.class), anyString(), anyString());
    }

    // @Test
    void shouldChangePasswordTestsVerifyAuthServiceIsCalledOnPasswordChange() throws Exception {
        when(authService.changePassword(any(NewPasswordUserRequest.class), anyString(), anyString()))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/auth/newPassword")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(changePasswordRequest)))
                .andExpect(status().isOk());

        verify(authService).changePassword(any(NewPasswordUserRequest.class), anyString(), anyString());
    }

    // @Test
    void shouldChangePasswordTestsReturnBadRequestWhenNewPasswordIsMissing() throws Exception {
        NewPasswordUserRequest invalidRequest = new NewPasswordUserRequest(null, "password123", refreshToken);

        mockMvc.perform(post("/api/auth/newPassword")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldChangePasswordTestsReturnBadRequestWhenConfirmPasswordIsMissing() throws Exception {
        NewPasswordUserRequest invalidRequest = new NewPasswordUserRequest("password123", null, refreshToken);

        mockMvc.perform(post("/api/auth/newPassword")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldChangePasswordTestsReturnBadRequestWhenTokenIsMissing() throws Exception {
        NewPasswordUserRequest invalidRequest = new NewPasswordUserRequest("password123", "password123", null);

        mockMvc.perform(post("/api/auth/newPassword")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // @Test
    void shouldChangePasswordTestsReturnBadRequestWhenBodyIsEmpty() throws Exception {
        mockMvc.perform(post("/api/auth/newPassword")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());
    }
}
