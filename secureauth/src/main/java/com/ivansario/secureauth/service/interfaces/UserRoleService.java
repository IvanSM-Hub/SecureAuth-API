package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserRole;

public interface UserRoleService {

    List<UserRole> findAll();
    UserRole findById(UUID id);
    UserRole create(User user, Role role);
    UserRole update(UserRole userRole);
    boolean delete(UUID id);

}
