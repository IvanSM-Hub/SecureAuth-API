package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;

public interface RefreshTokenService {

    List<RefreshToken> findAll();
    RefreshToken findById(UUID id);
    RefreshToken findByUser(User user);
    RefreshToken findByToken(String token);
    RefreshToken create(User user, String ipAddress, String userAgent);
    RefreshToken revokeToken(RefreshToken foundRefreshToken);
    void revokeAllTokensByUser(User user);
    boolean delete(UUID id);
    RefreshToken updateToken(RefreshToken existingRefreshToken, String ipAddress, String userAgent);
    boolean existsRefreshTokenByUser(User user);
    boolean deleteByUser(User user);

}
