package com.ivansario.secureauth.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.hibernate.validator.internal.constraintvalidators.bv.EmailValidator;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.UpdateUserProfileRequest;
import com.ivansario.secureauth.dto.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.UserResponse;
import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.exception.InvalidCredentialsException;
import com.ivansario.secureauth.exception.RefreshTokenRevokedException;
import com.ivansario.secureauth.exception.SessionRevokeException;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.repository.UserRepository;
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
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
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

        User user = User.builder()
        .username(createUserRequest.getUsername())
        .name(createUserRequest.getName())
        .surname(createUserRequest.getSurname())
        .email(createUserRequest.getEmail())
        .passwordHash(passwordEncoder.encode(createUserRequest.getPassword()))
        .role(role)
        .build();

        return userRepository.save(user);

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
        
        if (passwordEncoder.matches(newPassword, oldEncryptPassword)) {
            throw new InvalidCredentialsException("The password you want to modify must be different from the existing one");
        }

        String encryptNewPassword = passwordEncoder.encode(newPassword);

        user.setPasswordHash(encryptNewPassword);

        User userNewPassword = userRepository.save(user);

        if (!passwordEncoder.matches(newPassword, userNewPassword.getPasswordHash())) {
            throw new InvalidCredentialsException("The password could not be updated correctly for the user: " + userNewPassword.getSurname());
        }

        return userRepository.save(user);
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
    public UserResponse updateUserProfile(String userId, UpdateUserProfileRequest updateUser) {

        UUID uuidUser = UUID.fromString(userId);
        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + userId));

        String updatedUsername = updateUser.getUsername();
        String updatedName = updateUser.getName();
        String updatedSurname = updateUser.getSurname();

        if (updatedUsername == null && updatedName == null && updatedSurname == null) {
            log.error("The attributes to update the user are null;");
            throw new IllegalArgumentException("The attributes to update the user are null;");
        }

        if (updatedUsername != null && !updatedUsername.isBlank()) {
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
    public UserResponse updateUserRole(String userId, UpdateUserRoleRequest updateUser) {
        UUID uuidUser = UUID.fromString(userId);
        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + userId));

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
        
        UUID uuidUser = UUID.fromString(userId);

        User userFinded = userRepository.findById(uuidUser).orElseThrow(() -> new UserNotFoundException("User not Found by uuid: " + userId));
        userFinded.setEnabled(false);
        userFinded.setUpdatedAt(LocalDateTime.now());

        UserSession userSession = userSessionService.findByUser(userFinded);
        userSession.setRevoked(true);
        if (!userSession.isRevoked()) {
            log.error("It can't be possible revoke the session from the user: " + userFinded.getEmail());
            throw new SessionRevokeException("It can't be possible revoke the session from the user: " + userFinded.getEmail());
        }

        RefreshToken refreshToken = refreshTokenService.findByUser(userFinded);
        RefreshToken revokedToken = refreshTokenService.revokeToken(refreshToken);
        if (!revokedToken.isRevoked()) {
            log.error("It can't be possible revoke the token from the user: " + userFinded.getEmail());
            throw new RefreshTokenRevokedException("It can't be possible revoke the token from the user: " + userFinded.getEmail());
        }

        userRepository.save(userFinded);

        return UserResponse.builder()
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
