package com.ivansario.secureauth.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserProtection;

public interface UserProtectionRepository extends JpaRepository<UserProtection, UUID> {
    
    boolean isBlockUser(User user);

}
