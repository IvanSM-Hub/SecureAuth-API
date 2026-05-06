package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.service.interfaces.UserSessionService;

public class UserSessionServiceImpl implements UserSessionService {

    @Override
    public List<UserSession> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserSession findById(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserSession create(UserSession session) {
        throw new UnsupportedOperationException("Not implemented");
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
