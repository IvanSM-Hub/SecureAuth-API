package com.ivansario.secureauth.service.interfaces;

import java.util.UUID;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;

public interface UserService {

    User findUser(String userKey);
    User createUser(CreateUserRequest createUserRequest, Role role);
    User changePassword(NewPasswordUserRequest newPassword);
    User deleteUser(UUID id);
    User updateUser(User user);

    boolean existsUser(String userKey);

}
