package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RolePermission;

public interface RolePermissionService {

    List<RolePermission> findAll();
    RolePermission findById(UUID id);
    RolePermission create(RolePermission rp);
    RolePermission update(RolePermission rp);
    boolean delete(UUID id);

}
