package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RolePermission;

/**
 * Service contract for role-permission assignments.
 */
public interface RolePermissionService {

    /**
     * Returns all role-permission assignments.
     *
     * @return all assignments
     */
    List<RolePermission> findAll();

    /**
     * Finds a role-permission assignment by identifier.
     *
     * @param id assignment id
     * @return matching assignment
     */
    RolePermission findById(UUID id);

    /**
     * Creates a role-permission assignment.
     *
     * @param rp assignment to persist
     * @return persisted assignment
     */
    RolePermission create(RolePermission rp);

    /**
     * Updates a role-permission assignment.
     *
     * @param rp assignment to update
     * @return updated assignment
     */
    RolePermission update(RolePermission rp);

    /**
     * Deletes a role-permission assignment by identifier.
     *
     * @param id assignment id
     * @return {@code true} when deletion succeeded
     */
    boolean delete(UUID id);

}
