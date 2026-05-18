package com.ivansario.secureauth.service;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
public class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImpl userService;

    private User testUser;

    private final String username = "usernametest";

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .username(username)
                .email("test@email.com")
                .passwordHash("encoded_pass")
                .build();
    }

    @Nested
    class CreateUserTests {
        @Test
        void shouldCreateUserSuccessfully() {

            CreateUserRequest request = CreateUserRequest.builder()
            .email("test@email.com")
            .username("ivan")
            .name

        }
    }

    @Nested
    class FindUserTests {
        @Test
        void shouldFindUserByEmail() {
            // lógica del test...
        }

        @Test
        void shouldThrowExceptionWhenNotFound() {
            // lógica del test...
        }
    }

    @Nested
    class ChangePasswordTests {
        @Test
        void shouldFailIfPasswordIsSame() {
            // lógica del test...
        }
    }

}
