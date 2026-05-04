package com.ivansario.secureauth.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserRole;

public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {
    List<UserRole> findAllByUser(User user);
    List<UserRole> findAllByRole(Role role);
    boolean existsByUserAndRole(User user, Role role);
    void deleteByUserAndRole(User user, Role role);
}