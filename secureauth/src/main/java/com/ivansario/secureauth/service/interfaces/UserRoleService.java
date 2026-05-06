package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.UserRole;

public interface UserRoleService {

    List<UserRole> findAll();
    UserRole findById(UUID id);
    UserRole create(UserRole userRole);
    UserRole update(UserRole userRole);
    boolean delete(UUID id);

}
