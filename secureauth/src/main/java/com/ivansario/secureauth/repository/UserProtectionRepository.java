package com.ivansario.secureauth.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserProtection;

public interface UserProtectionRepository extends JpaRepository<UserProtection, UUID> {
    
    @Query("SELECT up.active FROM UserProtection up WHERE user.id = :userId")
    boolean isBlockUser(User user);

}
