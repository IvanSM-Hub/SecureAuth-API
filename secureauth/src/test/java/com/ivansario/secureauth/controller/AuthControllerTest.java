package com.ivansario.secureauth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import com.ivansario.secureauth.Controller.AuthController;
import com.ivansario.secureauth.dto.auth.AuthResponse;
import com.ivansario.secureauth.dto.auth.LoginRequest;
import com.ivansario.secureauth.dto.auth.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.auth.RefreshTokenRequest;
import com.ivansario.secureauth.exception.GlobalExceptionHandler;
import com.ivansario.secureauth.service.interfaces.AuthService;

import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

@ExtendWith(MockitoExtension.class)
class AuthControllerITest {

    @Mock
    private AuthService authService;

    private MockMvc mockMvc;
    private final JsonMapper objectMapper = JsonMapper.builder().findAndAddModules().build();

    private LoginRequest loginRequest;
    private RefreshTokenRequest refreshTokenRequest;
    private NewPasswordUserRequest newPasswordUserRequest;

    @BeforeEach
    void setUp() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        mockMvc = standaloneSetup(new AuthController(authService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setMessageConverters(new JacksonJsonHttpMessageConverter(objectMapper))
                .setValidator(validator)
                .build();

        loginRequest = LoginRequest.builder()
                .username("ivan.sario")
                .password("Password123!")
                .build();

        refreshTokenRequest = RefreshTokenRequest.builder()
                .token("refresh-token-1234567890")
                .build();

        newPasswordUserRequest = NewPasswordUserRequest.builder()
                .token("refresh-token-1234567890")
                .currentPassword("Password123!")
                .newPassword("Password456!")
                .confirmPassword("Password456!")
                .build();
    }

    @Test
    void loginShouldReturnTokens() throws Exception {
        AuthResponse response = AuthResponse.builder()
                .username("ivan.sario")
                .email("ivan@example.com")
                .role("ROLE_USER")
                .accessToken("access-token")
                .refreshToken("refresh-token")
                .build();

        when(authService.login(any(LoginRequest.class), any(), any())).thenReturn(response);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("User-Agent", "JUnit")
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value("ivan.sario"))
                .andExpect(jsonPath("$.email").value("ivan@example.com"))
                .andExpect(jsonPath("$.role").value("ROLE_USER"))
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"));
    }

    @Test
    void logoutShouldReturnNoContent() throws Exception {
        doNothing().when(authService).logout(any(RefreshTokenRequest.class));

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isNoContent());
    }

    @Test
    void refreshShouldReturnNewTokens() throws Exception {
        AuthResponse response = AuthResponse.builder()
                .username("ivan.sario")
                .email("ivan@example.com")
                .role("ROLE_USER")
                .accessToken("new-access-token")
                .refreshToken("new-refresh-token")
                .build();

        when(authService.refreshToken(any(RefreshTokenRequest.class), any(), any())).thenReturn(response);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("User-Agent", "JUnit")
                        .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));
    }

    @Test
    void changePasswordShouldReturnNewTokens() throws Exception {
        AuthResponse response = AuthResponse.builder()
                .username("ivan.sario")
                .email("ivan@example.com")
                .role("ROLE_USER")
                .accessToken("rotated-access-token")
                .refreshToken("rotated-refresh-token")
                .build();

        when(authService.changePassword(any(NewPasswordUserRequest.class), any(), any())).thenReturn(response);

        mockMvc.perform(post("/api/auth/newPassword")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("User-Agent", "JUnit")
                        .content(objectMapper.writeValueAsString(newPasswordUserRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("rotated-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("rotated-refresh-token"));
    }

    @Test
    void loginShouldRejectInvalidPayload() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed"))
                .andExpect(jsonPath("$.errors.username").value("Username or email is required"))
                .andExpect(jsonPath("$.errors.password").value("Password is required"));
    }
}