package com.ivansario.secureauth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserProtection;
import com.ivansario.secureauth.exception.UserProtectionException;
import com.ivansario.secureauth.repository.UserProtectionRepository;
import com.ivansario.secureauth.service.interfaces.UserService;

@ExtendWith(MockitoExtension.class)
class UserProtectionServiceImplTest {

    @Mock
    private UserProtectionRepository userProtectionRepository;

    @Mock
    private UserService userService;

    @InjectMocks
    private UserProtectionServiceImpl userProtectionService;

    private User user;
    private UserProtection ipProtection;
    private UserProtection userProtection;

    private final String username = "testuser";
    private final String ip = "192.168.1.1";

    @BeforeEach
    void setUp() {
        user = User.builder()
            .username(username)
            .email("test@email.com")
            .enabled(true)
            .build();

        ipProtection = UserProtection.builder()
            .ipOrigin(ip)
            .numTrys(2)
            .lastTry(LocalDateTime.now().minusMinutes(1))
            .active(false)
            .build();

        userProtection = UserProtection.builder()
            .user(user)
            .ipOrigin(ip)
            .numTrys(2)
            .lastTry(LocalDateTime.now().minusMinutes(1))
            .active(false)
            .build();
    }

    @Test
    void shouldRegisterFailedAttemptForIpAndUser() {
        when(userProtectionRepository.findByIpOrigin(ip)).thenReturn(Optional.of(ipProtection));
        when(userProtectionRepository.findByUser_Username(username)).thenReturn(Optional.of(userProtection));

        userProtectionService.registerFailedAttempt(username, ip);

        ArgumentCaptor<UserProtection> captor = ArgumentCaptor.forClass(UserProtection.class);
        verify(userProtectionRepository, times(2)).save(captor.capture());
        assertThat(captor.getAllValues()).hasSize(2);
        assertThat(captor.getAllValues().get(0).getNumTrys()).isEqualTo(3);
        assertThat(captor.getAllValues().get(1).getNumTrys()).isEqualTo(3);
    }

    @Test
    void shouldBlockWhenMaxAttemptsReached() {
        ipProtection.setNumTrys(4);
        userProtection.setNumTrys(4);
        when(userProtectionRepository.findByIpOrigin(ip)).thenReturn(Optional.of(ipProtection));
        when(userProtectionRepository.findByUser_Username(username)).thenReturn(Optional.of(userProtection));

        userProtectionService.registerFailedAttempt(username, ip);

        assertThat(ipProtection.getNumTrys()).isEqualTo(5);
        assertThat(ipProtection.getBloquedAt()).isNotNull();
        assertThat(ipProtection.isActive()).isTrue();
        assertThat(userProtection.getNumTrys()).isEqualTo(5);
        assertThat(userProtection.getBloquedAt()).isNotNull();
        assertThat(userProtection.isActive()).isTrue();
    }

    @Test
    void shouldResetBothOnSuccessfulLogin() {
        ipProtection.setNumTrys(4);
        ipProtection.setBloquedAt(LocalDateTime.now().plusMinutes(5));
        ipProtection.setActive(true);
        userProtection.setNumTrys(4);
        userProtection.setBloquedAt(LocalDateTime.now().plusMinutes(5));
        userProtection.setActive(true);

        when(userProtectionRepository.findByIpOrigin(ip)).thenReturn(Optional.of(ipProtection));
        when(userProtectionRepository.findByUser_Username(username)).thenReturn(Optional.of(userProtection));

        userProtectionService.registerSuccessfulLogin(username, ip);

        assertThat(ipProtection.getNumTrys()).isZero();
        assertThat(ipProtection.getBloquedAt()).isNull();
        assertThat(ipProtection.isActive()).isFalse();
        assertThat(userProtection.getNumTrys()).isZero();
        assertThat(userProtection.getBloquedAt()).isNull();
        assertThat(userProtection.isActive()).isFalse();
        verify(userProtectionRepository).save(ipProtection);
        verify(userProtectionRepository).save(userProtection);
    }

    @Test
    void shouldReturnBlockedUntilForIp() {
        UserProtection blocked = UserProtection.builder()
            .ipOrigin(ip)
            .bloquedAt(LocalDateTime.now().plusMinutes(10))
            .active(true)
            .numTrys(5)
            .build();
        when(userProtectionRepository.findByIpOrigin(ip)).thenReturn(Optional.of(blocked));

        assertThat(userProtectionService.getBlockedUntilForIp(ip)).isPresent();
    }

    @Test
    void shouldReturnZeroWhenUserProtectionNotFound() {
        when(userProtectionRepository.findByUser_Username(username)).thenReturn(Optional.empty());

        assertThat(userProtectionService.getFailedAttemptsForUser(username)).isZero();
    }

    @Test
    void shouldThrowWhenBothInputsMissingOnReset() {
        assertThrows(UserProtectionException.class,
            () -> userProtectionService.resetFailedAttempts(null, null));
    }

    @Test
    void shouldUnblockIpWhenRecordExists() {
        UserProtection blocked = UserProtection.builder()
            .ipOrigin(ip)
            .bloquedAt(LocalDateTime.now().plusMinutes(10))
            .active(true)
            .numTrys(5)
            .build();
        when(userProtectionRepository.findByIpOrigin(ip)).thenReturn(Optional.of(blocked));

        userProtectionService.unblockIp(ip);

        assertFalse(blocked.isActive());
        verify(userProtectionRepository).save(blocked);
    }

    @Test
    void shouldDoNothingWhenIpRecordDoesNotExist() {
        when(userProtectionRepository.findByIpOrigin(anyString())).thenReturn(Optional.empty());

        userProtectionService.unblockIp(ip);

        verify(userProtectionRepository, never()).save(any(UserProtection.class));
    }

    @Test
    void shouldBlockIpForConfiguredDuration() {
        when(userProtectionRepository.findByIpOrigin(ip)).thenReturn(Optional.empty());

        userProtectionService.blockIp(ip, Duration.ofMinutes(2));

        verify(userProtectionRepository).save(any(UserProtection.class));
    }
}