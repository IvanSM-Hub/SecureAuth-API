package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.repository.UserSessionRepository;
import com.ivansario.secureauth.service.interfaces.UserSessionService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserSessionServiceImpl implements UserSessionService {

    private final UserSessionRepository userSessionRepository;

    @Override
    public List<UserSession> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserSession findById(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserSession create(User user, RefreshToken refreshToken, String ipAddress, String UserAgent) {
        UserSession us = UserSession.builder()
        .user(user)
        .refreshToken(refreshToken)
        .ipAddress(ipAddress)
        .deviceInfo(UserAgent)
        .build();
        return userSessionRepository.save(us);
    }

    @Override
    public UserSession update(UserSession session) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

}
