package com.ivansario.secureauth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.repository.RefreshTokenRepository;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceImplTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenServiceImpl refreshTokenService;

    private User user;
    private RefreshToken refreshToken;

    private final String email = "test@email.com";
    private final String username = "usernametest";
    private final String ipAddress = "192.168.1.15";
    private final String userAgent = "Mozilla/5.0";
    private final String tokenValue = "refresh-token-value";

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
            .token(tokenValue)
            .expiryDate(LocalDateTime.now().plusDays(1))
            .revoked(false)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .build();
        refreshToken.setId(UUID.randomUUID());
    }

    @Nested
    class FindAllTests {

        @Test
        void shouldThrowUnsupportedOperationException() {
            UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> refreshTokenService.findAll()
            );

            assertThat(exception.getMessage()).contains("Not implemented");
        }
    }

    @Nested
    class FindByIdTests {

        @Test
        void shouldReturnRefreshTokenReferenceById() {
            UUID id = UUID.randomUUID();
            when(refreshTokenRepository.getReferenceById(id)).thenReturn(refreshToken);

            RefreshToken result = refreshTokenService.findById(id);

            assertSame(refreshToken, result);
            verify(refreshTokenRepository).getReferenceById(id);
        }
    }

    @Nested
    class CreateTests {

        @Test
        void shouldCreateRefreshTokenSuccessfully() {
            when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

            RefreshToken created = refreshTokenService.create(user, ipAddress, userAgent);

            assertSame(user, created.getUser());
            assertEquals(ipAddress, created.getIpAddress());
            assertEquals(userAgent, created.getUserAgent());
            assertFalse(created.isRevoked());
            assertThat(created.getToken()).isNotBlank();
            assertDoesNotThrow(() -> UUID.fromString(created.getToken()));
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }
    }

    @Nested
    class DeleteTests {

        @Test
        void shouldThrowUnsupportedOperationException() {
            UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> refreshTokenService.delete(UUID.randomUUID())
            );

            assertThat(exception.getMessage()).contains("Not implemented");
        }
    }

    @Nested
    class FindByTokenTests {

        @Test
        void shouldReturnRefreshTokenWhenTokenExists() {
            when(refreshTokenRepository.findByToken(tokenValue)).thenReturn(Optional.of(refreshToken));

            RefreshToken result = refreshTokenService.findByToken(tokenValue);

            assertSame(refreshToken, result);
            verify(refreshTokenRepository).findByToken(tokenValue);
        }

        @Test
        void shouldReturnNullWhenTokenDoesNotExist() {
            when(refreshTokenRepository.findByToken(tokenValue)).thenReturn(Optional.empty());

            RefreshToken result = refreshTokenService.findByToken(tokenValue);

            assertNull(result);
            verify(refreshTokenRepository).findByToken(tokenValue);
        }
    }

    @Nested
    class FindByUserTests {

        @Test
        void shouldReturnRefreshTokenWhenUserExists() {
            when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.of(refreshToken));

            RefreshToken result = refreshTokenService.findByUser(user);

            assertSame(refreshToken, result);
            verify(refreshTokenRepository).findByUser(user);
        }

        @Test
        void shouldReturnNullWhenUserDoesNotHaveToken() {
            when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.empty());

            RefreshToken result = refreshTokenService.findByUser(user);

            assertNull(result);
            verify(refreshTokenRepository).findByUser(user);
        }
    }

    @Nested
    class RevokeTokenTests {

        @Test
        void shouldRevokeTokenSuccessfully() {
            when(refreshTokenRepository.save(refreshToken)).thenAnswer(invocation -> invocation.getArgument(0));

            RefreshToken revokedToken = refreshTokenService.revokeToken(refreshToken);

            assertSame(refreshToken, revokedToken);
            assertTrue(revokedToken.isRevoked());
            verify(refreshTokenRepository).save(refreshToken);
        }
    }

    @Nested
    class RevokeAllTokensByUserTests {

        @Test
        void shouldRevokeAllTokensForUserSuccessfully() {
            RefreshToken firstToken = RefreshToken.builder()
                .user(user)
                .token("token-1")
                .revoked(false)
                .build();
            firstToken.setId(UUID.randomUUID());

            RefreshToken secondToken = RefreshToken.builder()
                .user(user)
                .token("token-2")
                .revoked(false)
                .build();
            secondToken.setId(UUID.randomUUID());

            when(refreshTokenRepository.findAllByUser(user)).thenReturn(List.of(firstToken, secondToken));

            refreshTokenService.revokeAllTokensByUser(user);

            assertTrue(firstToken.isRevoked());
            assertTrue(secondToken.isRevoked());
            verify(refreshTokenRepository).findAllByUser(user);
            verify(refreshTokenRepository).saveAll(anyList());
        }
    }

    @Nested
    class UpdateTokenTests {

        @Test
        void shouldUpdateTokenSuccessfully() {
            LocalDateTime beforeUpdate = LocalDateTime.now();
            when(refreshTokenRepository.save(refreshToken)).thenAnswer(invocation -> invocation.getArgument(0));

            RefreshToken updatedToken = refreshTokenService.updateToken(refreshToken, ipAddress, userAgent);

            assertSame(refreshToken, updatedToken);
            assertEquals(ipAddress, updatedToken.getIpAddress());
            assertEquals(userAgent, updatedToken.getUserAgent());
            assertFalse(updatedToken.isRevoked());
            assertThat(updatedToken.getToken()).isNotEqualTo(tokenValue);
            assertDoesNotThrow(() -> UUID.fromString(updatedToken.getToken()));
            assertThat(updatedToken.getExpiryDate()).isAfterOrEqualTo(beforeUpdate.plusDays(1));
            verify(refreshTokenRepository).save(refreshToken);
        }
    }

    @Nested
    class ExistsRefreshTokenByUserTests {

        @Test
        void shouldReturnTrueWhenTokenExistsForUser() {
            when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.of(refreshToken));

            boolean exists = refreshTokenService.existsRefreshTokenByUser(user);

            assertTrue(exists);
            verify(refreshTokenRepository).findByUser(user);
        }

        @Test
        void shouldReturnFalseWhenTokenDoesNotExistForUser() {
            when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.empty());

            boolean exists = refreshTokenService.existsRefreshTokenByUser(user);

            assertFalse(exists);
            verify(refreshTokenRepository).findByUser(user);
        }
    }

    @Nested
    class DeleteByUserTests {

        @Test
        void shouldDeleteRefreshTokenWhenExists() {
            when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.of(refreshToken));

            boolean deleted = refreshTokenService.deleteByUser(user);

            assertTrue(deleted);
            verify(refreshTokenRepository).findByUser(user);
            verify(refreshTokenRepository).delete(refreshToken);
        }

        @Test
        void shouldReturnFalseWhenRefreshTokenDoesNotExist() {
            when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.empty());

            boolean deleted = refreshTokenService.deleteByUser(user);

            assertFalse(deleted);
            verify(refreshTokenRepository).findByUser(user);
        }
    }
}