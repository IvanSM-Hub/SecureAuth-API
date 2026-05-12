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
 * Servicio para gestión de Refresh Tokens.
 *
 * Implementa creación, búsqueda, actualización y revocación de refresh tokens.
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
     * Crea un nuevo {@link RefreshToken} asociado al usuario y lo persiste.
     *
     * @param user      usuario asociado al token
     * @param ipAddress dirección IP desde la que se creó el token
     * @param userAgent información del cliente
     * @return el {@link RefreshToken} creado y persistido
     */

    @Override
    public RefreshToken create(User user, String ipAddress, String userAgent) {
        RefreshToken rt = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .ipAdress(ipAddress)
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
     * Busca el refresh token por token.
     *
     * @param token valor del refresh token
     * @return el {@link RefreshToken} o {@code null} si no existe
     */
    @Override
    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token).orElse(null);
    }

    /**
     * Busca el refresh token por Usuario.
     *
     * @param user valor del refresh token
     * @return el {@link RefreshToken} o {@code null} si no existe
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
     * Revoca todos los refresh tokens asociados a un usuario.
     *
     * @param user usuario cuyas tokens serán revocadas
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
        existingRefreshToken.setIpAdress(ipAddress);
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

}
