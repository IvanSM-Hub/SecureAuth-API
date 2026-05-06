package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.Permission;

public interface PermissionService {

    List<Permission> findAll();
    Permission findById(UUID id);
    Permission create(Permission permission);
    Permission update(Permission permission);
    boolean delete(UUID id);

}
