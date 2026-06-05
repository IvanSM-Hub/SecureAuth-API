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

/**
 * Service contract for user lifecycle and profile operations.
 */
public interface UserService extends UserDetailsService {

    /**
     * Finds a user by username or email.
     *
     * @param userKey username or email
     * @return matching user
     */
    User findUser(String userKey);

    /**
     * Returns all users as API responses.
     *
     * @return list of users
     */
    List<UserResponse> getAllUsers();

    /**
     * Creates a user with a given role.
     *
     * @param createUserRequest user creation payload
     * @param role role to assign
     * @return persisted user
     */
    User createUser(CreateUserRequest createUserRequest, Role role);

    /**
     * Updates a user entity.
     *
     * @param user user to update
     * @return updated user
     */
    User updateUser(User user);

    /**
     * Checks whether a user exists by username or email.
     *
     * @param userKey username or email
     * @return {@code true} when the user exists
     */
    boolean existsUser(String userKey);

    /**
     * Changes the password of an existing user.
     *
     * @param user target user
     * @param newPassword new raw password
     * @return updated user
     */
    User changePassword(User user, String newPassword);

    /**
     * Registers a new user and returns public registration data.
     *
     * @param request user registration payload
     * @param ipAddress client IP address
     * @param userAgent client user-agent
     * @param roleEnum role to assign to the new user
     * @return registration response
     */
    RegisterResponse register(CreateUserRequest request, String ipAddress, String userAgent, RoleEnum roleEnum);

    /**
     * Returns a user profile by identifier.
     *
     * @param userId user id as string
     * @return user response
     */
    UserResponse getUserById(String userId);

    /**
     * Updates a user's profile fields.
     *
     * @param updateUser update payload
     * @return updated user response
     */
    UserResponse updateUserProfile(UpdateUserProfileRequest updateUser);

    /**
     * Updates a user's role.
     *
     * @param updateUser role update payload
     * @return updated user response
     */
    UserResponse updateUserRole(UpdateUserRoleRequest updateUser);

    /**
     * Soft-deletes a user and revokes active credentials.
     *
     * @param userId user id as string
     * @return updated user response
     */
    UserResponse virtualDeleteUser(String userId);

    /**
     * Re-activates a previously disabled user.
     *
     * @param userId user id as string
     * @return updated user response
     */
    UserResponse activateUser(String userId);

    /**
     * Permanently removes a user and related session/token records.
     *
     * @param userId user id as string
     * @return {@code true} when deletion completed successfully
     */
    boolean permanentlyDeleteUser(String userId);

}
