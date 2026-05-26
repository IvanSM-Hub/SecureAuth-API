package com.ivansario.secureauth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.repository.UserSessionRepository;

@ExtendWith(MockitoExtension.class)
class UserSessionServiceImplTest {

    @Mock
    private UserSessionRepository userSessionRepository;

    @InjectMocks
    private UserSessionServiceImpl userSessionService;

    private User user;
    private RefreshToken refreshToken;
    private UserSession userSession;

    private final String email = "test@email.com";
    private final String username = "usernametest";
    private final String ipAddress = "192.168.1.100";
    private final String userAgent = "Mozilla/5.0 Chrome/91.0";

    @BeforeEach
    void setUp() {
        user = User.builder()
            .username(username)
            .email(email)
            .passwordHash("password_hash")
            .name("Name")
            .surname("Surname")
            .build();
        user.setId(UUID.randomUUID());

        refreshToken = RefreshToken.builder()
            .user(user)
            .token(UUID.randomUUID().toString())
            .expiryDate(LocalDateTime.now().plusDays(1))
            .revoked(false)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .build();
        refreshToken.setId(UUID.randomUUID());

        userSession = UserSession.builder()
            .user(user)
            .refreshToken(refreshToken)
            .ipAddress(ipAddress)
            .deviceInfo(userAgent)
            .revoked(false)
            .build();
        userSession.setId(UUID.randomUUID());
    }

    @Nested
    class FindAllTests {

        @Test
        void shouldThrowUnsupportedOperationException() {
            UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> userSessionService.findAll()
            );

            assertThat(exception.getMessage()).contains("Not implemented");
        }
    }

    @Nested
    class FindByIdTests {

        @Test
        void shouldThrowUnsupportedOperationException() {
            UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> userSessionService.findById(UUID.randomUUID())
            );

            assertThat(exception.getMessage()).contains("Not implemented");
        }
    }

    @Nested
    class CreateTests {

        @Test
        void shouldCreateUserSessionSuccessfully() {
            when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> {
                UserSession session = invocation.getArgument(0);
                session.setId(UUID.randomUUID());
                return session;
            });

            UserSession created = userSessionService.create(user, refreshToken, ipAddress, userAgent);

            assertSame(user, created.getUser());
            assertSame(refreshToken, created.getRefreshToken());
            assertEquals(ipAddress, created.getIpAddress());
            assertEquals(userAgent, created.getDeviceInfo());
            assertFalse(created.isRevoked());
            assertThat(created.getId()).isNotNull();
            verify(userSessionRepository).save(any(UserSession.class));
        }

        @Test
        void shouldCreateMultipleSessionsForDifferentRefreshTokens() {
            when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> {
                UserSession session = invocation.getArgument(0);
                session.setId(UUID.randomUUID());
                return session;
            });

            RefreshToken anotherToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(LocalDateTime.now().plusDays(1))
                .revoked(false)
                .build();
            anotherToken.setId(UUID.randomUUID());

            UserSession firstSession = userSessionService.create(user, refreshToken, ipAddress, userAgent);
            UserSession secondSession = userSessionService.create(user, anotherToken, "192.168.1.101", "Safari");

            assertSame(user, firstSession.getUser());
            assertSame(user, secondSession.getUser());
            assertNotEquals(firstSession.getRefreshToken().getId(), secondSession.getRefreshToken().getId());
        }
    }

    @Nested
    class UpdateTests {

        @Test
        void shouldUpdateUserSessionSuccessfully() {
            when(userSessionRepository.save(userSession)).thenAnswer(invocation -> invocation.getArgument(0));

            userSession.setRevoked(true);
            UserSession updatedSession = userSessionService.update(userSession);

            assertSame(userSession, updatedSession);
            assertTrue(updatedSession.isRevoked());
            verify(userSessionRepository).save(userSession);
        }

        @Test
        void shouldUpdateLastActivityOnSessionUpdate() {
            when(userSessionRepository.save(userSession)).thenAnswer(invocation -> invocation.getArgument(0));

            UserSession updatedSession = userSessionService.update(userSession);

            assertSame(userSession, updatedSession);
            verify(userSessionRepository).save(userSession);
        }
    }

    @Nested
    class FindByUserTests {

        @Test
        void shouldReturnUserSessionWhenUserExists() {
            when(userSessionRepository.findByUser(user)).thenReturn(Optional.of(userSession));

            UserSession result = userSessionService.findByUser(user);

            assertSame(userSession, result);
            verify(userSessionRepository).findByUser(user);
        }

        @Test
        void shouldReturnNullWhenUserDoesNotHaveSession() {
            when(userSessionRepository.findByUser(user)).thenReturn(Optional.empty());

            UserSession result = userSessionService.findByUser(user);

            assertNull(result);
            verify(userSessionRepository).findByUser(user);
        }
    }

    @Nested
    class RevokeLastSessionTests {

        @Test
        void shouldRevokeLastSessionSuccessfully() {
            UserSession activeSession = UserSession.builder()
                .user(user)
                .refreshToken(refreshToken)
                .ipAddress(ipAddress)
                .deviceInfo(userAgent)
                .revoked(false)
                .build();
            activeSession.setId(UUID.randomUUID());

            when(userSessionRepository.findByUser(user)).thenReturn(Optional.of(activeSession));
            when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

            boolean revoked = userSessionService.revokeSession(user);

            assertTrue(revoked);
            assertTrue(activeSession.isRevoked());
            verify(userSessionRepository).findByUser(user);
            verify(userSessionRepository).save(activeSession);
        }

        @Test
        void shouldReturnFalseWhenUserHasNoSession() {
            when(userSessionRepository.findByUser(user)).thenReturn(Optional.empty());

            boolean revoked = userSessionService.revokeSession(user);

            assertFalse(revoked);
            verify(userSessionRepository).findByUser(user);
        }

        @Test
        void shouldReturnFalseWhenSessionIsAlreadyRevoked() {
            UserSession revokedSession = UserSession.builder()
                .user(user)
                .refreshToken(refreshToken)
                .ipAddress(ipAddress)
                .deviceInfo(userAgent)
                .revoked(true)
                .build();
            revokedSession.setId(UUID.randomUUID());

            when(userSessionRepository.findByUser(user)).thenReturn(Optional.of(revokedSession));

            boolean revoked = userSessionService.revokeSession(user);

            assertFalse(revoked);
            assertTrue(revokedSession.isRevoked());
            verify(userSessionRepository).findByUser(user);
        }

        @Test
        void shouldUpdateLastActivityWhenRevokingSession() {
            LocalDateTime beforeRevoke = LocalDateTime.now();
            when(userSessionRepository.findByUser(user)).thenReturn(Optional.of(userSession));
            when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

            userSessionService.revokeSession(user);

            ArgumentCaptor<UserSession> sessionCaptor = ArgumentCaptor.forClass(UserSession.class);
            verify(userSessionRepository).save(sessionCaptor.capture());
            UserSession savedSession = sessionCaptor.getValue();
            
            assertTrue(savedSession.isRevoked());
            assertThat(savedSession.getLastActivity()).isAfterOrEqualTo(beforeRevoke);
        }
    }

    @Nested
    class DeleteByUserTests {

        @Test
        void shouldDeleteSessionWhenExists() {
            when(userSessionRepository.findByUser(user)).thenReturn(Optional.of(userSession));

            boolean deleted = userSessionService.deleteByUser(user);

            assertTrue(deleted);
            verify(userSessionRepository).findByUser(user);
            verify(userSessionRepository).delete(userSession);
        }

        @Test
        void shouldReturnFalseWhenSessionDoesNotExist() {
            when(userSessionRepository.findByUser(user)).thenReturn(Optional.empty());

            boolean deleted = userSessionService.deleteByUser(user);

            assertFalse(deleted);
            verify(userSessionRepository).findByUser(user);
        }
    }
}
