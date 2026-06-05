package com.ivansario.secureauth.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.repository.UserSessionRepository;
import com.ivansario.secureauth.service.interfaces.UserSessionService;

import lombok.RequiredArgsConstructor;

/**
 * Service for user session management.
 *
 * Supports creation, update, lookup, and revocation of user sessions.
 */
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
        .revoked(false)
        .build();
        return userSessionRepository.save(us);
    }

    /**
     * Updates a persisted user session.
     *
     * @param session session to update
     * @return updated session
     */
    @Override
    public UserSession update(UserSession session) {
        return userSessionRepository.save(session);
    }

    @Override
    public UserSession findByUser(User user) {
        return userSessionRepository.findByUser(user).orElse(null);
    }

    /**
     * Revokes the active session for a user when present.
     *
     * @param user user whose session will be revoked
     * @return {@code true} when a session was revoked; otherwise {@code false}
     */
    @Override
    public boolean revokeSession(User user) {
        UserSession session = findByUser(user);
        
        if (session == null || session.isRevoked()) return false;

        session.setRevoked(true);
        session.setLastActivity(LocalDateTime.now());
        userSessionRepository.save(session);
        return true;
    }

    @Override
    public boolean deleteByUser(User user) {
        UserSession session = findByUser(user);
        if (session != null) {
            userSessionRepository.delete(session);
            return true;
        }
        return false;
    }

}
