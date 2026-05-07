package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;

public interface UserSessionService {

    List<UserSession> findAll();
    UserSession findById(UUID id);
    UserSession create(User user, RefreshToken rt, String ip, String ua);
    UserSession update(UserSession session);
    boolean delete(UUID id);

}
