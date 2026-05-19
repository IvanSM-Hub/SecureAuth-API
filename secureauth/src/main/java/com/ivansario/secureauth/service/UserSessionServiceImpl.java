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
 * Servicio para gestión de sesiones de usuario.
 *
 * Permite crear, actualizar, buscar y revocar sesiones asociadas a usuarios.
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
     * Actualiza la sesión en persistencia.
     *
     * @param session sesión a actualizar
     * @return sesión actualizada
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
     * Revoca la última sesión activa del usuario (si existe).
     *
     * @param user usuario cuya sesión será revocada
     * @return {@code true} si la sesión fue revocada, {@code false} si no había sesión
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

}
