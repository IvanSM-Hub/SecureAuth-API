package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.UserRole;
import com.ivansario.secureauth.service.interfaces.UserRoleService;

public class UserRoleServiceImpl implements UserRoleService {

    @Override
    public List<UserRole> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserRole findById(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserRole create(UserRole userRole) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserRole update(UserRole userRole) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

}
