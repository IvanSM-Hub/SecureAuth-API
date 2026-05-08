package com.ivansario.secureauth.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ivansario.secureauth.entity.Permission;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.RolePermission;
import com.ivansario.secureauth.util.RolePermissionId;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermission, RolePermissionId> {
    List<RolePermission> findAllByRole(Role role);
    List<RolePermission> findAllByPermission(Permission permission);
    boolean existsByRoleAndPermission(Role role, Permission permission);
    void deleteByRoleAndPermission(Role role, Permission permission);
}