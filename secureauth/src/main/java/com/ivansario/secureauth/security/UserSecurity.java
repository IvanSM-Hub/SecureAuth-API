package com.ivansario.secureauth.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.service.interfaces.UserService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component("userSecurity")
public class UserSecurity {

    private final UserService userService;

    public boolean isOwner(String userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null || auth.getName().isBlank()) {
            return false;
        }

        try {
            User authenticatedUser = userService.findUser(auth.getName());
            return authenticatedUser.getId() != null && authenticatedUser.getId().toString().equals(userId);
        } catch (Exception ex) {
            return false;
        }
    }

}
