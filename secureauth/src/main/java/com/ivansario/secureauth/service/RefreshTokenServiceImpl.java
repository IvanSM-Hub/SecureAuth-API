package com.ivansario.secureauth.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.repository.RefreshTokenRepository;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;

import lombok.RequiredArgsConstructor;

/**
 * Service for managing Refresh Tokens.
 *
 * Implements creation, retrieval, update and revocation of refresh tokens.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public List<RefreshToken> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public RefreshToken findById(UUID id) {
        return refreshTokenRepository.getReferenceById(id);
    }

    /**
     * Creates a new {@link RefreshToken} associated to the user and persists it.
     *
     * @param user      user associated to the token
     * @param ipAddress IP address where the token was created
     * @param userAgent client info
     * @return the created and persisted {@link RefreshToken}
     */

    @Override
    public RefreshToken create(User user, String ipAddress, String userAgent) {
        RefreshToken rt = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .revoked(false)
                .build();
        return refreshTokenRepository.save(rt);
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    /**
     * Finds the refresh token by token value.
     *
     * @param token token value
     * @return the {@link RefreshToken} or {@code null} if not found
     */
    @Override
    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token).orElse(null);
    }

    /**
     * Finds the refresh token by user.
     *
     * @param user user value
     * @return the {@link RefreshToken} or {@code null} if not found
     */
    @Override
    public RefreshToken findByUser(User user) {
        return refreshTokenRepository.findByUser(user).orElse(null);
    }

    @Override
    public RefreshToken revokeToken(RefreshToken foundRefreshToken) {
        foundRefreshToken.setRevoked(true);
        return refreshTokenRepository.save(foundRefreshToken);
    }

    /**
     * Revokes all refresh tokens associated to a user.
     *
     * @param user user whose tokens will be revoked
     */
    @Override
    public void revokeAllTokensByUser(User user) {
        List<RefreshToken> userTokens = refreshTokenRepository.findAllByUser(user);
        userTokens.forEach(token -> token.setRevoked(true));
        refreshTokenRepository.saveAll(userTokens);
    }

    @Override
    public RefreshToken updateToken(RefreshToken existingRefreshToken, String ipAddress, String userAgent) {
        existingRefreshToken.setExpiryDate(LocalDateTime.now().plusDays(1));
        existingRefreshToken.setToken(UUID.randomUUID().toString());
        existingRefreshToken.setRevoked(false);
        existingRefreshToken.setIpAddress(ipAddress);
        existingRefreshToken.setUserAgent(userAgent);
        return refreshTokenRepository.save(existingRefreshToken);
    }

    /**
     * Comprueba si existe al menos un refresh token para el usuario.
     *
     * @param user usuario a verificar
     * @return {@code true} si existe al menos un token, {@code false} en caso
     *         contrario
     */
    @Override
    public boolean existsRefreshTokenByUser(User user) {
        return findByUser(user) != null;
    }

    @Override
    public boolean deleteByUser(User user) {
        RefreshToken token = findByUser(user);
        if (token != null) {
            refreshTokenRepository.delete(token);
            return true;
        }
        return false;
    }

}
