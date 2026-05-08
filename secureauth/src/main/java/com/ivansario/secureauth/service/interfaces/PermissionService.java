package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.Permission;
import com.ivansario.secureauth.util.PermissionEnum;
import com.ivansario.secureauth.util.RoleEnum;

public interface PermissionService {

    List<Permission> findAll();
    Permission findById(UUID id);
    Permission findByName(PermissionEnum permission);
    List<Permission> findPermissionByRole(RoleEnum roleType);
    Permission create(Permission permission);
    Permission update(Permission permission);
    boolean delete(UUID id);

}
