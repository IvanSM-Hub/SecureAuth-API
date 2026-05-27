package com.ivansario.secureauth.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.service.interfaces.UserService;

@ExtendWith(MockitoExtension.class)
class UserSecurityTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserSecurity userSecurity;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldReturnTrueWhenAuthenticatedUserMatchesTargetUuid() {
        UUID userId = UUID.randomUUID();
        User user = User.builder().id(userId).username("testuser").build();

        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("testuser", "password")
        );
        when(userService.findUser("testuser")).thenReturn(user);

        assertTrue(userSecurity.isOwner(userId.toString()));
    }

    @Test
    void shouldReturnFalseWhenAuthenticatedUserDoesNotMatchTargetUuid() {
        User user = User.builder().id(UUID.randomUUID()).username("testuser").build();

        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("testuser", "password")
        );
        when(userService.findUser("testuser")).thenReturn(user);

        assertFalse(userSecurity.isOwner(UUID.randomUUID().toString()));
    }

    @Test
    void shouldReturnFalseWhenNoAuthenticationExists() {
        SecurityContextHolder.clearContext();

        assertFalse(userSecurity.isOwner(UUID.randomUUID().toString()));
    }
}