package com.ivansario.secureauth.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserRole;
import com.ivansario.secureauth.util.UserRoleId;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, UserRoleId> {
    List<UserRole> findAllByUser(User user);
    List<UserRole> findAllByRole(Role role);
    boolean existsByUserAndRole(User user, Role role);
    void deleteByUserAndRole(User user, Role role);
}