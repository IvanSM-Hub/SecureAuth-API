package com.ivansario.secureauth.service.interfaces;

import java.util.UUID;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.UpdateUserRequest;
import com.ivansario.secureauth.dto.UserResponse;

public interface UserService {

    UserResponse findUser();
    UserResponse createUser(CreateUserRequest createUserRequest);
    UserResponse changePassword(NewPasswordUserRequest newPassword);
    UserResponse deleteUser(UUID id);
    UserResponse updateUser(UpdateUserRequest updateUser);

}
