package com.ivansario.secureauth.service.interfaces;

import java.util.List;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.ivansario.secureauth.dto.user.CreateUserRequest;
import com.ivansario.secureauth.dto.user.RegisterResponse;
import com.ivansario.secureauth.dto.user.UpdateUserProfileRequest;
import com.ivansario.secureauth.dto.user.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.user.UserResponse;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.util.RoleEnum;

public interface UserService extends UserDetailsService {

    User findUser(String userKey);
    List<UserResponse> getAllUsers();
    User createUser(CreateUserRequest createUserRequest, Role role);
    User updateUser(User user);
    boolean existsUser(String userKey);
    User changePassword(User user, String newPassword);
    RegisterResponse register(CreateUserRequest request, String ipAddress, String userAgent, RoleEnum roleEnum);
    UserResponse getUserById(String userId);
    UserResponse updateUserProfile(UpdateUserProfileRequest updateUser);
    UserResponse updateUserRole(UpdateUserRoleRequest updateUser);
    UserResponse virtualDeleteUser(String userId);
    UserResponse activateUser(String userId);
    boolean permanentlyDeleteUser(String userId);

}
