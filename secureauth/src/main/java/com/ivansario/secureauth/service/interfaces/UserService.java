package com.ivansario.secureauth.service.interfaces;

import java.util.List;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.UpdateUserProfileRequest;
import com.ivansario.secureauth.dto.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.UserResponse;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;

public interface UserService {

    User findUser(String userKey);
    List<UserResponse> getAllUsers();
    User createUser(CreateUserRequest createUserRequest, Role role);
    User updateUser(User user);
    boolean existsUser(String userKey);
    User changePassword(User user, String newPassword);
    UserResponse getUserById(String userId);
    UserResponse updateUserProfile(String userId, UpdateUserProfileRequest updateUser);
    UserResponse updateUserRole(String userId, UpdateUserRoleRequest updateUser);
    UserResponse virtualDeleteUser(String userId);
    UserResponse activateUser(String userId);
    boolean permanentlyDeleteUser(String userId);

}
