package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;

public interface RefreshTokenService {

    List<RefreshToken> findAll();
    RefreshToken findById(UUID id);
    RefreshToken create(User user, String ipAddress, String userAgent);
    RefreshToken update(RefreshToken token);
    boolean delete(UUID id);

}
