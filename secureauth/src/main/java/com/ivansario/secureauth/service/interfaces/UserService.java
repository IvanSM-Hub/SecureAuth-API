package com.ivansario.secureauth.service.interfaces;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;

public interface UserService {

    User findUser(String userKey);
    User createUser(CreateUserRequest createUserRequest, Role role);
    User updateUser(User user);
    boolean existsUser(String userKey);

}
