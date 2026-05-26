package com.ivansario.secureauth.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.ivansario.secureauth.entity.User;

@Component("userSecurity")
public class UserSecurity {

    public boolean isOwner(String userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return false;

        Object principal = auth.getPrincipal();

        if (principal instanceof User) {
            User user = (User) principal;
            if (user.getId() != null && user.getId().toString().equals(userId)) {
                return true;
            }
            return user.getUsername() != null && user.getUsername().equals(userId);
        }

        if (principal instanceof org.springframework.security.core.userdetails.User) {
            org.springframework.security.core.userdetails.User secUser = 
            (org.springframework.security.core.userdetails.User) principal;
            return secUser.getUsername().equals(userId);
        }

        if (principal instanceof String) {
            return principal.equals(userId);
        }

        return false;
    }

}
