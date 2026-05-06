package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.Role;

public interface RoleService {

    List<Role> findAll();
    Role findById(UUID id);
    Role create(Role role);
    Role update(Role role);
    boolean delete(UUID id);

}
