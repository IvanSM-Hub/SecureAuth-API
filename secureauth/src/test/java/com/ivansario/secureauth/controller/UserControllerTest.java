package com.ivansario.secureauth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.Controller.UserController;
import com.ivansario.secureauth.dto.user.UpdateUserProfileRequest;
import com.ivansario.secureauth.dto.user.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.user.UserResponse;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.exception.GlobalExceptionHandler;
import com.ivansario.secureauth.service.interfaces.UserService;
import com.ivansario.secureauth.util.RoleEnum;

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
class UserControllerITest {

    @Mock
    private UserService userService;

    private MockMvc mockMvc;
    private final JsonMapper objectMapper = JsonMapper.builder().findAndAddModules().build();

    private UUID userId;
    private User ownerUser;
    private UserResponse userResponse;
    private UserResponse updatedResponse;
    private UserResponse roleResponse;

    @BeforeEach
    void setUp() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        mockMvc = standaloneSetup(new UserController(userService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setMessageConverters(new JacksonJsonHttpMessageConverter(objectMapper))
                .setValidator(validator)
                .build();

        userId = UUID.fromString("11111111-1111-1111-1111-111111111111");

        Role userRole = Role.builder()
                .name(RoleEnum.ROLE_USER)
                .description("Standard user")
                .build();
        userRole.setId(UUID.randomUUID());

        ownerUser = User.builder()
                .username("owner@example.com")
                .email("owner@example.com")
                .name("Owner")
                .surname("User")
                .passwordHash("hash")
                .enabled(true)
                .role(userRole)
                .build();
        ownerUser.setId(userId);
        ownerUser.setCreatedAt(LocalDateTime.now().minusDays(1));
        ownerUser.setUpdatedAt(LocalDateTime.now());

        userResponse = UserResponse.builder()
                .username("owner@example.com")
                .email("owner@example.com")
                .role("ROLE_USER")
                .completeName("Owner User")
                .createdAt(ownerUser.getCreatedAt())
                .updatedAt(ownerUser.getUpdatedAt())
                .lastLogin(LocalDateTime.now().minusHours(2))
                .isActive(true)
                .build();

        updatedResponse = UserResponse.builder()
                .username("owner.updated@example.com")
                .email("owner@example.com")
                .role("ROLE_USER")
                .completeName("Owner Updated")
                .createdAt(ownerUser.getCreatedAt())
                .updatedAt(LocalDateTime.now())
                .lastLogin(ownerUser.getLastLogin())
                .isActive(true)
                .build();

        roleResponse = UserResponse.builder()
                .username("owner@example.com")
                .email("owner@example.com")
                .role("ROLE_ADMIN")
                .completeName("Owner User")
                .createdAt(ownerUser.getCreatedAt())
                .updatedAt(LocalDateTime.now())
                .lastLogin(ownerUser.getLastLogin())
                .isActive(true)
                .build();

    }

    @Test
    void getAllUsersShouldReturnList() throws Exception {
                when(userService.getAllUsers()).thenReturn(List.of(userResponse));

        mockMvc.perform(get("/api/user/all"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$[0].username").value("owner@example.com"))
                .andExpect(jsonPath("$[0].role").value("ROLE_USER"));
    }

    @Test
    void getUserShouldReturnProfile() throws Exception {
                when(userService.getUserById(userId.toString())).thenReturn(userResponse);

        mockMvc.perform(get("/api/user/{userId}", userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("owner@example.com"))
                .andExpect(jsonPath("$.completeName").value("Owner User"));
    }

    @Test
    void updateProfileShouldReturnUpdatedUser() throws Exception {
        UpdateUserProfileRequest request = UpdateUserProfileRequest.builder()
                .username("owner.updated@example.com")
                .name("Owner")
                .surname("Updated")
                .build();

        when(userService.updateUserProfile(anyString(), any(UpdateUserProfileRequest.class))).thenReturn(updatedResponse);

        mockMvc.perform(put("/api/user/update/{userId}", userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("owner.updated@example.com"))
                .andExpect(jsonPath("$.completeName").value("Owner Updated"));
    }

    @Test
    void updateProfileShouldRejectInvalidPayload() throws Exception {
        mockMvc.perform(put("/api/user/update/{userId}", userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"ab\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed"))
                .andExpect(jsonPath("$.errors.username").value("Username must be between 3 and 100 characters"));
    }

    @Test
    void updateRoleShouldWork() throws Exception {
        UpdateUserRoleRequest request = UpdateUserRoleRequest.builder()
                .roleName("ROLE_ADMIN")
                .build();

        when(userService.updateUserRole(anyString(), any(UpdateUserRoleRequest.class))).thenReturn(roleResponse);

        mockMvc.perform(put("/api/user/role/{userId}", userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ROLE_ADMIN"));
    }

    @Test
    void virtualDeleteShouldReturnUser() throws Exception {
        when(userService.virtualDeleteUser(userId.toString())).thenReturn(userResponse);

        mockMvc.perform(put("/api/user/delete/{userId}", userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("owner@example.com"));
    }

    @Test
    void activateUserShouldReturnUser() throws Exception {
        when(userService.activateUser(userId.toString())).thenReturn(userResponse);

        mockMvc.perform(put("/api/user/active/{userId}", userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("owner@example.com"));
    }

    @Test
    void permanentlyDeleteShouldReturnTrue() throws Exception {
        when(userService.permanentlyDeleteUser(userId.toString())).thenReturn(true);

        mockMvc.perform(delete("/api/user/permanentlyDelete/{userId}", userId))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));
    }
}