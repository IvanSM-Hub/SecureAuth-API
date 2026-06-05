package com.ivansario.secureauth.repository;

import java.util.UUID;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import com.ivansario.secureauth.entity.UserProtection;

public interface UserProtectionRepository extends JpaRepository<UserProtection, UUID> {

    
    
    @Override
    @EntityGraph(attributePaths = {"user", "user.role"})
    List<UserProtection> findAll();

    @EntityGraph(attributePaths = {"user", "user.role"})
    Optional<UserProtection> findByUser_Username(String username);

    @EntityGraph(attributePaths = {"user", "user.role"})
    Optional<UserProtection> findFirstByUser_UsernameOrderByLastTryDesc(String username);

    @EntityGraph(attributePaths = {"user", "user.role"})
    Optional<UserProtection> findByUser_Email(String email);

    @EntityGraph(attributePaths = {"user", "user.role"})
    Optional<UserProtection> findFirstByUser_EmailOrderByLastTryDesc(String email);

    @EntityGraph(attributePaths = {"user", "user.role"})
    Optional<UserProtection> findByIpOrigin(String ipOrigin);

}
