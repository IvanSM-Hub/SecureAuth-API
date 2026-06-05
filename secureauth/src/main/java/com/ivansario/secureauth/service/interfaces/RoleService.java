package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.util.RoleEnum;

/**
 * Service contract for role management.
 */
public interface RoleService {

    /**
     * Returns all roles.
     *
     * @return list of roles
     */
    List<Role> findAll();

    /**
     * Finds a role by enum name.
     *
     * @param role role enum value
     * @return matching role
     */
    Role findByName(RoleEnum role);

    /**
     * Finds a role by identifier.
     *
     * @param id role id
     * @return matching role
     */
    Role findById(UUID id);

    /**
     * Creates a role.
     *
     * @param role role entity
     * @return persisted role
     */
    Role create(Role role);

    /**
     * Updates a role.
     *
     * @param role role entity
     * @return updated role
     */
    Role update(Role role);

    /**
     * Deletes a role by identifier.
     *
     * @param id role id
     * @return {@code true} when deletion succeeded
     */
    boolean delete(UUID id);

}
