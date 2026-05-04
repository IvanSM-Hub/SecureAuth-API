package com.ivansario.secureauth.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ivansario.secureauth.entity.Permission;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.RolePermission;

public interface RolePermissionRepository extends JpaRepository<RolePermission, UUID> {
    List<RolePermission> findAllByRole(Role role);
    List<RolePermission> findAllByPermission(Permission permission);
    boolean existsByRoleAndPermission(Role role, Permission permission);
    void deleteByRoleAndPermission(Role role, Permission permission);
}