package com.ivansario.secureauth.service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserProtection;
import com.ivansario.secureauth.exception.UserProtectionException;
import com.ivansario.secureauth.repository.UserProtectionRepository;
import com.ivansario.secureauth.service.interfaces.UserProtectionService;
import com.ivansario.secureauth.service.interfaces.UserService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserProtectionServiceImpl implements UserProtectionService {

    private final UserProtectionRepository userProtectionRepository;
    private final UserServiceImpl userService;

    @Override
    public void blockIp(String ip, Duration duration) {
        if (ip.isEmpty() || duration.isNegative()) {
            throw new UserProtectionException("Somthing was wrong on attemption of loging");
        }

    }

    @Override
    public void blockUser(String username, Duration duration) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public Optional<Instant> getBlockedUntilForIp(String ip) {
        // TODO Auto-generated method stub
        return Optional.empty();
    }

    @Override
    public Optional<Instant> getBlockedUntilForUser(String username) {
        // TODO Auto-generated method stub
        return Optional.empty();
    }

    @Override
    public int getFailedAttemptsForIp(String ip) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public int getFailedAttemptsForUser(String username) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean isBlocked(String username, String ip) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isIpBlocked(String ip) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isUserBlocked(String username) {
        if (username == null || username.isEmpty()) {
            throw new UserProtectionException("The username provided is wrong");
        }
        
        String normalizedUsername = username.trim();
        User user = userService.findUser(normalizedUsername);

        UserProtection userProtection = userProtectionRepository.findById(user.getId()).orElse(null);
        if (userProtection == null) {
            throw new UserProtectionException("The User Protection from " + normalizedUsername + " is not found");
        }

        if (userProtection.getBloquedAt().isBefore(LocalDateTime.now()) 
            && !userProtection.isActive()) {
            return true;
        }

        return false;
    }

    @Override
    public void registerFailedAttempt(String username, String ip) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void registerSuccessfulLogin(String username, String ip) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void resetFailedAttempts(String username, String ip) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void unblockIp(String ip) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void unblockUser(String username) {
        // TODO Auto-generated method stub
        
    }

}
