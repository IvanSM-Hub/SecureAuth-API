package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.repository.RoleRepository;
import com.ivansario.secureauth.service.interfaces.RoleService;
import com.ivansario.secureauth.util.RoleEnum;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Override
    public List<Role> findAll() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Role findById(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Role create(Role role) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Role update(Role role) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean delete(UUID id) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Role findByName(RoleEnum role) {
        return roleRepository.findByName(role).orElse(null);
    }

}
