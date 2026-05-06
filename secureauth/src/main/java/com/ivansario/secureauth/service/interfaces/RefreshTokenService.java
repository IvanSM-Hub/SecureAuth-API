package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RefreshToken;

public interface RefreshTokenService {

    List<RefreshToken> findAll();
    RefreshToken findById(UUID id);
    RefreshToken create(RefreshToken token);
    RefreshToken update(RefreshToken token);
    boolean delete(UUID id);

}
