package com.ivansario.secureauth.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.util.RoleEnum;

public interface RoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findByName(RoleEnum name);
    boolean existsByName(RoleEnum name);
}