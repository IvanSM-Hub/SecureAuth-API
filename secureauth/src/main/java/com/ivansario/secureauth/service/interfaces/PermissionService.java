package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.Permission;
import com.ivansario.secureauth.util.PermissionEnum;
import com.ivansario.secureauth.util.RoleEnum;

/**
 * Service contract for permission management.
 */
public interface PermissionService {

    /**
     * Returns every permission in the system.
     *
     * @return all permissions
     */
    List<Permission> findAll();

    /**
     * Finds a permission by identifier.
     *
     * @param id permission id
     * @return matching permission
     */
    Permission findById(UUID id);

    /**
     * Finds a permission by enum name.
     *
     * @param permission permission enum value
     * @return matching permission
     */
    Permission findByName(PermissionEnum permission);

    /**
     * Returns permissions associated with a role.
     *
     * @param roleType role enum value
     * @return permissions allowed for the role
     */
    List<Permission> findPermissionByRole(RoleEnum roleType);

    /**
     * Creates a permission.
     *
     * @param permission permission entity
     * @return persisted permission
     */
    Permission create(Permission permission);

    /**
     * Updates a permission.
     *
     * @param permission permission entity
     * @return updated permission
     */
    Permission update(Permission permission);

    /**
     * Deletes a permission by identifier.
     *
     * @param id permission id
     * @return {@code true} when deletion succeeded
     */
    boolean delete(UUID id);

}
