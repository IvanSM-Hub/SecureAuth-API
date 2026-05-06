package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.Permission;
import com.ivansario.secureauth.service.interfaces.PermissionService;

public class PermissionServiceImpl implements PermissionService {

    @Override
    public List<Permission> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Permission findById(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Permission create(Permission permission) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Permission update(Permission permission) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

}
