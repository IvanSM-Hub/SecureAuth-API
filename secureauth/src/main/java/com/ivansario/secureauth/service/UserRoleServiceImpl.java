package com.ivansario.secureauth.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserRole;
import com.ivansario.secureauth.repository.UserRoleRepository;
import com.ivansario.secureauth.service.interfaces.UserRoleService;
import com.ivansario.secureauth.util.UserRoleId;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserRoleServiceImpl implements UserRoleService {

    private final UserRoleRepository userRoleRepository;

    @Override
    public List<UserRole> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserRole findById(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public UserRole create(User user, Role role) {

        UserRoleId id = UserRoleId.builder()
        .userId(user.getId())
        .roleId(role.getId())
        .build();
        
        UserRole userRole = new UserRole();

        userRole.setId(id);
        userRole.setUser(user);
        userRole.setRole(role);
        userRole.setAssignedAt(LocalDateTime.now());

        return userRoleRepository.save(userRole);
    }

    @Override
    public UserRole update(UserRole userRole) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

}
