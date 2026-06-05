package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.entity.RolePermission;
import com.ivansario.secureauth.service.interfaces.RolePermissionService;

/**
 * Service implementation for role-permission relationships.
 *
 * All methods are currently placeholders and throw
 * {@link UnsupportedOperationException}.
 */
@Service
public class RolePermissionServiceImpl implements RolePermissionService {


    @Override
    public List<RolePermission> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public RolePermission findById(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public RolePermission create(RolePermission rp) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public RolePermission update(RolePermission rp) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

}
