package com.ivansario.secureauth.repository;

import java.util.UUID;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ivansario.secureauth.entity.UserProtection;

public interface UserProtectionRepository extends JpaRepository<UserProtection, UUID> {
    
    Optional<UserProtection> findByUser_Username(String username);

    Optional<UserProtection> findByIpOrigin(String ipOrigin);

}
