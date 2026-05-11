package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.repository.RefreshTokenRepository;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;

import lombok.RequiredArgsConstructor;

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

    @Override
    public RefreshToken create(User user, String ipAddress, String userAgent) {
        RefreshToken rt = RefreshToken.builder()
        .user(user)
        .token(UUID.randomUUID().toString())
        .ipAdress(ipAddress)
        .userAgent(userAgent)
        .build();
        return refreshTokenRepository.save(rt);
    }

    @Override
    public RefreshToken update(RefreshToken oldRefreshToken) {
        oldRefreshToken.setRevoked(true);
        return refreshTokenRepository.save(oldRefreshToken);
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token).orElse(null);
    }

}
