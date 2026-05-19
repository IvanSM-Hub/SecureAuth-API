package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;

public interface UserSessionService {

    List<UserSession> findAll();
    UserSession findById(UUID id);
    UserSession findByUser(User user);
    UserSession create(User user, RefreshToken refreshToken, String ipAddress, String UserAgent);
    UserSession update(UserSession session);
    boolean revokeSession(User user);
    
}
