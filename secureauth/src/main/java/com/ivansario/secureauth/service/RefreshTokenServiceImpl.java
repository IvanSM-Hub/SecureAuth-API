package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;

public class RefreshTokenServiceImpl implements RefreshTokenService {

    @Override
    public List<RefreshToken> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public RefreshToken findById(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public RefreshToken create(RefreshToken token) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public RefreshToken update(RefreshToken token) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

}
