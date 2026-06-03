package com.ivansario.secureauth.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.hibernate.validator.internal.constraintvalidators.bv.EmailValidator;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.user.CreateUserRequest;
import com.ivansario.secureauth.dto.user.UpdateUserProfileRequest;
import com.ivansario.secureauth.dto.user.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.user.UserResponse;
import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.exception.InvalidCredentialsException;
import com.ivansario.secureauth.exception.RefreshTokenRevokedException;
import com.ivansario.secureauth.exception.SessionRevokeException;
import com.ivansario.secureauth.exception.UserCreationException;
import com.ivansario.secureauth.exception.UserExistsException;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.repository.UserRepository;
import com.ivansario.secureauth.service.interfaces.PasswordSecurityService;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.RoleService;
import com.ivansario.secureauth.service.interfaces.UserService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;
import com.ivansario.secureauth.util.RoleEnum;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordSecurityService passwordSecurityService;
    private final RoleService roleService;
    private final UserSessionService userSessionService;
    private final RefreshTokenService refreshTokenService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        try {
            return loadUserDetailsWithAuthorities(email);
        } catch (EntityNotFoundException ex) {
            throw new UsernameNotFoundException("User not found: " + email, ex);
        }
    }

    @Transactional(readOnly = true)
    protected UserDetails loadUserDetailsWithAuthorities(String userKey) {
        validateUserKey(userKey);

        EmailValidator emailValidator = new EmailValidator();
        boolean isEmail = emailValidator.isValid(userKey, null);

        User user = (isEmail
                ? userRepository.findByEmailWithRoles(userKey)
                : userRepository.findByUsernameWithRoles(userKey))
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userKey));

        var authorities = user.getRole() != null
                ? List.of(new SimpleGrantedAuthority(user.getRole().getName().name()))
                : List.<SimpleGrantedAuthority>of();

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPasswordHash(),
                user.getEnabled(),
                true,
                true,
                true,
                authorities
        );
    }

    @Override
    public User createUser(CreateUserRequest createUserRequest, Role role) {
        try {
            
            User user = User.builder()
            .username(createUserRequest.getUsername())
            .name(createUserRequest.getName())
            .surname(createUserRequest.getSurname())
            .email(createUserRequest.getEmail())
            .passwordHash(passwordSecurityService.encryptPassword(createUserRequest.getPassword()))
            .role(role)
            .build();
    
            return userRepository.save(user);

        } catch (DataIntegrityViolationException e) {
            log.warn("User creation failed due to unique/constraint violation for email {}", createUserRequest.getEmail(), e);
            throw new UserExistsException("The provided username or email is already in use");
        } catch (RuntimeException e) {
            log.error("Unexpected error while creating user with email {}", createUserRequest.getEmail(), e);
            throw new UserCreationException("User could not be created", e);
        }

    }

    @Override
    public User updateUser(User user) {
        return userRepository.save(user);
    }
    
    @Override
    public User findUser(String userKey) {
        validateUserKey(userKey);

        EmailValidator emailValidator = new EmailValidator();
        boolean isEmail = emailValidator.isValid(userKey, null);

        return (isEmail
                ? userRepository.findByEmail(userKey)
                : userRepository.findByUsername(userKey))
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userKey));
    }

    @Override
    public boolean existsUser(String userKey) {
        validateUserKey(userKey);
        return userKey.contains("@")
        ? userRepository.existsByEmail(userKey)
        : userRepository.existsByUsername(userKey);
    }

    private void validateUserKey(String userKey) {
        if (userKey == null || userKey.isBlank()) {
            log.warn("An attempt was made to search for a user with a null or empty key");
            throw new IllegalArgumentException("The search key cannot be empty");
        }
    }

    @Override
    public User changePassword(User user, String newPassword) {
        
        String oldEncryptPassword = user.getPassword();
        
        if (passwordSecurityService.matches(newPassword, oldEncryptPassword)) {
            throw new InvalidCredentialsException("The password you want to modify must be different from the existing one");
        }

        String encryptNewPassword = passwordSecurityService.encryptPassword(newPassword);

        user.setPasswordHash(encryptNewPassword);

        User userNewPassword = userRepository.save(user);

        if (!passwordSecurityService.matches(newPassword, userNewPassword.getPasswordHash())) {
            throw new InvalidCredentialsException("The password could not be updated correctly for the user: " + userNewPassword.getSurname());
        }

        return userNewPassword;
    }

    @Override
    public List<UserResponse> getAllUsers() {

        List<User> users = userRepository.findAllWithRoles();
        if (users.isEmpty()) {
            log.info("Users not found in the database");
            throw new EntityNotFoundException("Users not found in the database");
        }

        List<UserResponse> userResponses = users.stream()
                .map(user -> UserResponse.builder()
                .id(user.getId() != null ? user.getId().toString() : null)
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .role(user.getRole() != null ? user.getRole().getName().name() : null)
                        .completeName(UserResponse.generateCompleteName(user.getName(), user.getSurname()))
                        .createdAt(user.getCreatedAt())
                        .updatedAt(user.getUpdatedAt())
                        .lastLogin(user.getLastLogin())
                        .isActive(user.isEnabled())
                        .build())
                .toList();
        return userResponses;
    }

    @Override
    public UserResponse getUserById(String userId) {
        
        UUID uuidUser = UUID.fromString(userId);
        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + userId));
        
        return UserResponse.builder()
        .id(userFinded.getId() != null ? userFinded.getId().toString() : null)
        .username(userFinded.getUsername())
        .email(userFinded.getEmail())
        .role(userFinded.getRole().getName().name())
        .completeName(UserResponse.generateCompleteName(userFinded.getName(), userFinded.getSurname()))
        .createdAt(userFinded.getCreatedAt())
        .updatedAt(userFinded.getUpdatedAt())
        .lastLogin(userFinded.getLastLogin())
        .isActive(userFinded.isEnabled())
        .build();
        
    }

    @Override
    @Transactional
    public UserResponse updateUserProfile(UpdateUserProfileRequest updateUser) {

        UUID uuidUser = UUID.fromString(updateUser.getId());
        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + updateUser.getId()));

        String updatedUsername = updateUser.getUsername();
        String updatedName = updateUser.getName();
        String updatedSurname = updateUser.getSurname();

        if (updatedUsername == null && updatedName == null && updatedSurname == null) {
            log.error("The attributes to update the user are null;");
            throw new IllegalArgumentException("The attributes to update the user are null;");
        }

        if (updatedUsername != null && !updatedUsername.isBlank()) {
            EmailValidator emailValidator = new EmailValidator();
            boolean isEmail = emailValidator.isValid(updatedUsername, null);
            if (isEmail) {
                log.error("The username provided is a email and is not posible to update");
                throw new IllegalArgumentException("The username provided is a email and is not posible to update");
            }

            Optional<User> existingUser = userRepository.findByUsername(updatedUsername.trim());
            if (existingUser.isPresent() && !existingUser.get().getId().equals(uuidUser)) {
                throw new UserExistsException("The username provided is in use by another user");
            }

            userFinded.setUsername(updatedUsername.trim());
        }
        if (updatedName != null && !updatedName.isBlank()) {
            userFinded.setName(updatedName.trim());
        }
        if (updatedSurname != null && !updatedSurname.isBlank()) {
            userFinded.setSurname(updatedSurname.trim());
        }

        userFinded.setUpdatedAt(LocalDateTime.now());

        userRepository.save(userFinded);

        return UserResponse.builder()
        .id(userFinded.getId() != null ? userFinded.getId().toString() : null)
        .username(userFinded.getUsername())
        .email(userFinded.getEmail())
        .role(userFinded.getRole().getName().name())
        .completeName(UserResponse.generateCompleteName(userFinded.getName(), userFinded.getSurname()))
        .createdAt(userFinded.getCreatedAt())
        .updatedAt(userFinded.getUpdatedAt())
        .lastLogin(userFinded.getLastLogin())
        .isActive(userFinded.isEnabled())
        .build();

    }

    @Override
    @Transactional
    public UserResponse updateUserRole(UpdateUserRoleRequest updateUser) {
        UUID uuidUser = UUID.fromString(updateUser.getId());
        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + updateUser.getId()));

        String updatedRole = updateUser.getRoleName();

        if (updatedRole == null) {
            log.error("The attributes to update the user are null;");
            throw new IllegalArgumentException("The attributes to update the user are null;");
        }

        Role role = roleService.findByName(RoleEnum.valueOf(updatedRole));

        userFinded.setRole(role);

        userFinded.setUpdatedAt(LocalDateTime.now());

        userRepository.save(userFinded);

        return UserResponse.builder()
        .id(userFinded.getId() != null ? userFinded.getId().toString() : null)
        .username(userFinded.getUsername())
        .email(userFinded.getEmail())
        .role(userFinded.getRole().getName().name())
        .completeName(UserResponse.generateCompleteName(userFinded.getName(), userFinded.getSurname()))
        .createdAt(userFinded.getCreatedAt())
        .updatedAt(userFinded.getUpdatedAt())
        .lastLogin(userFinded.getLastLogin())
        .isActive(userFinded.isEnabled())
        .build();
    }

    @Override
    @Transactional
    public UserResponse virtualDeleteUser(String userId) {
        if (userId == null || userId.isBlank()) {
            log.error("The id provided is null");
            throw new IllegalArgumentException("The id provided is null");
        }
        
        UUID uuidUser = UUID.fromString(userId);

        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + userId));
        userFinded.setEnabled(false);
        userFinded.setUpdatedAt(LocalDateTime.now());

        UserSession userSession = userSessionService.findByUser(userFinded);
        if (userSession == null) {
            throw new SessionRevokeException("Session not found for: " + userFinded.getEmail());
        }
        userSession.setRevoked(true);
        if (!userSession.isRevoked()) {
            log.error("It can't be possible revoke the session from the user: " + userFinded.getEmail());
            throw new SessionRevokeException("It can't be possible revoke the session from the user: " + userFinded.getEmail());
        }

        RefreshToken refreshToken = refreshTokenService.findByUser(userFinded);
        if (refreshToken == null) {
            log.error("Token not found by User: " + userFinded.getEmail());
            throw new RefreshTokenRevokedException("Token not found by User: " + userFinded.getEmail());
        }
        RefreshToken revokedToken = refreshTokenService.revokeToken(refreshToken);
        if (!revokedToken.isRevoked()) {
            log.error("It can't be possible revoke the token from the user: " + userFinded.getEmail());
            throw new RefreshTokenRevokedException("It can't be possible revoke the token from the user: " + userFinded.getEmail());
        }

        userRepository.save(userFinded);

        return UserResponse.builder()
        .id(userFinded.getId() != null ? userFinded.getId().toString() : null)
        .username(userFinded.getUsername())
        .email(userFinded.getEmail())
        .role(userFinded.getRole().getName().name())
        .completeName(UserResponse.generateCompleteName(userFinded.getName(), userFinded.getSurname()))
        .createdAt(userFinded.getCreatedAt())
        .updatedAt(userFinded.getUpdatedAt())
        .lastLogin(userFinded.getLastLogin())
        .isActive(userFinded.isEnabled())
        .build();
    }

    @Override
    @Transactional
    public UserResponse activateUser(String userId) {
        
        UUID uuidUser = UUID.fromString(userId);

        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + userId));

        userFinded.setEnabled(true);
        userFinded.setUpdatedAt(LocalDateTime.now());

        userRepository.save(userFinded);

        return UserResponse.builder()
        .id(userFinded.getId() != null ? userFinded.getId().toString() : null)
        .username(userFinded.getUsername())
        .email(userFinded.getEmail())
        .role(userFinded.getRole().getName().name())
        .completeName(UserResponse.generateCompleteName(userFinded.getName(), userFinded.getSurname()))
        .createdAt(userFinded.getCreatedAt())
        .updatedAt(userFinded.getUpdatedAt())
        .lastLogin(userFinded.getLastLogin())
        .isActive(userFinded.isEnabled())
        .build();
    }

    @Override
    @Transactional
    public boolean permanentlyDeleteUser(String userId) {

        UUID uuidUser = UUID.fromString(userId);

        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + userId));

        boolean sessionDeleted = userSessionService.deleteByUser(userFinded);
        boolean tokenDeleted = refreshTokenService.deleteByUser(userFinded);
        if (!sessionDeleted || !tokenDeleted) {
            log.error("It can't be possible delete the user: " + userFinded.getEmail());
            throw new IllegalStateException("It can't be possible delete the user: " + userFinded.getEmail());
        }

        userRepository.delete(userFinded);
        
        return true;
    }

}
