package com.ivansario.secureauth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.ivansario.secureauth.dto.user.CreateUserRequest;
import com.ivansario.secureauth.dto.user.RegisterResponse;
import com.ivansario.secureauth.dto.user.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.user.UserResponse;
import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.exception.InvalidCredentialsException;
import com.ivansario.secureauth.exception.UserCreationException;
import com.ivansario.secureauth.exception.UserExistsException;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.repository.UserRepository;
import com.ivansario.secureauth.service.interfaces.PasswordSecurityService;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.RoleService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;
import com.ivansario.secureauth.util.RoleEnum;

import jakarta.persistence.EntityNotFoundException;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordSecurityService passwordSecurityService;

    @Mock
    private RoleService roleService;

    @Mock
    private UserSessionService userSessionService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private UserServiceImpl userService;

    private User testUser;
    private User testRoleUser;
    private CreateUserRequest createUserRequest;
    private Role roleAdmin;
    private Role roleUser;
    private List<UserResponse> usersResponse = new ArrayList<>();

    private final String name = "nametest";
    private final String surname = "surnametest";
    private final String username = "usernametest";
    private final String email = "test@email.com";
    private final String password = "encoded_pass";
    private final String hashedPassword = "hashed_pass";
    private final String newPassword = "new_password";

    @BeforeEach
    void setUp() {
        testUser = User.builder()
            .username(username)
            .email(email)
            .passwordHash(password)
            .name(name)
            .surname(surname)
            .enabled(true)
            .build();
        testUser.setId(UUID.randomUUID());

        createUserRequest = CreateUserRequest.builder()
            .email(email)
            .username(username)
            .name(name)
            .surname(surname)
            .password(password)
            .build();

        roleAdmin = Role.builder()
            .name(RoleEnum.ROLE_ADMIN)
            .description("Full system access with all permissions")
            .build();
        testUser.setRole(roleAdmin);

        testRoleUser = User.builder()
            .username("testusername2")
            .email("testemail2@gmail.com")
            .passwordHash("passwordhash2")
            .name("testname2")
            .surname("testSurname2")
            .enabled(true)
            .build();
        testRoleUser.setId(UUID.randomUUID());

        roleUser = Role.builder()
            .name(RoleEnum.ROLE_USER)
            .description("Standard user with limited permissions")
            .build();
        testRoleUser.setRole(roleUser);

        usersResponse.add(
            UserResponse.builder()
            .username(testUser.getUsername())
            .email(testUser.getEmail())
            .role(testUser.getRole().getName().name())
            .completeName(UserResponse.generateCompleteName(testUser.getName(), testUser.getSurname()))
            .createdAt(testUser.getCreatedAt())
            .updatedAt(testUser.getUpdatedAt())
            .lastLogin(testUser.getLastLogin())
            .isActive(testUser.isEnabled())
            .build()
        );
        usersResponse.add(
            UserResponse.builder()
            .username(testRoleUser.getUsername())
            .email(testRoleUser.getEmail())
            .role(testRoleUser.getRole().getName().name())
            .completeName(UserResponse.generateCompleteName(testRoleUser.getName(), testRoleUser.getSurname()))
            .createdAt(testRoleUser.getCreatedAt())
            .updatedAt(testRoleUser.getUpdatedAt())
            .lastLogin(testRoleUser.getLastLogin())
            .isActive(testRoleUser.isEnabled())
            .build()
        );
    }

    @Nested
    class RegisterTests {

        private final String ipAddress = "192.168.1.1";
        private final String userAgent = "Mozilla/5.0...";

        @Test
        void shouldRegisterUserSuccessfully() {
            UUID generatedId = UUID.randomUUID();

            when(userRepository.existsByEmail(email)).thenReturn(false);
            when(roleService.findByName(RoleEnum.ROLE_USER)).thenReturn(roleUser);
            when(passwordSecurityService.encryptPassword(createUserRequest.getPassword())).thenReturn(hashedPassword);
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User userToPersist = invocation.getArgument(0);
                userToPersist.setId(generatedId);
                return userToPersist;
            });

            RegisterResponse response = userService.register(createUserRequest, ipAddress, userAgent, RoleEnum.ROLE_USER);

            assertEquals(username, response.getUsername());
            assertEquals(email, response.getEmail());
            assertEquals(RoleEnum.ROLE_USER.name(), response.getRole());
            verify(roleService).findByName(RoleEnum.ROLE_USER);
            verify(passwordSecurityService).encryptPassword(createUserRequest.getPassword());
            verify(userRepository).save(any(User.class));
        }

        @Test
        void shouldThrowWhenUserAlreadyExists() {
            when(userRepository.existsByEmail(email)).thenReturn(true);

            assertThrows(UserExistsException.class,
                () -> userService.register(createUserRequest, ipAddress, userAgent, RoleEnum.ROLE_USER));
        }

        @Test
        void shouldThrowWhenRoleNotFound() {
            when(userRepository.existsByEmail(email)).thenReturn(false);
            when(roleService.findByName(RoleEnum.ROLE_ADMIN)).thenReturn(null);

            assertThrows(IllegalArgumentException.class,
                () -> userService.register(createUserRequest, ipAddress, userAgent, RoleEnum.ROLE_ADMIN));
        }

        @Test
        void shouldThrowWhenUserCreationFails() {
            when(userRepository.existsByEmail(email)).thenReturn(false);
            when(roleService.findByName(RoleEnum.ROLE_USER)).thenReturn(roleUser);
            when(passwordSecurityService.encryptPassword(createUserRequest.getPassword())).thenReturn(hashedPassword);
            when(userRepository.save(any(User.class))).thenReturn(null);

            assertThrows(UserCreationException.class,
                () -> userService.register(createUserRequest, ipAddress, userAgent, RoleEnum.ROLE_USER));
        }
    }

    @Nested
    class CreateUserTests {

        @Test
        void shouldCreateUserSuccessfully() {
            UUID generatedId = UUID.randomUUID();

            when(passwordSecurityService.encryptPassword(password)).thenReturn(hashedPassword);
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User userToPersist = invocation.getArgument(0);
                userToPersist.setId(generatedId);
                return userToPersist;
            });

            User userCreated = userService.createUser(createUserRequest, roleAdmin);

            assertEquals(name, userCreated.getName());
            assertEquals(surname, userCreated.getSurname());
            assertEquals(username, userCreated.getUsername());
            assertEquals(email, userCreated.getEmail());
            assertEquals(hashedPassword, userCreated.getPasswordHash());
            assertEquals(roleAdmin, userCreated.getRole());
            assertEquals(generatedId, userCreated.getId());
            verify(passwordSecurityService).encryptPassword(password);
            verify(userRepository).save(any(User.class));
            assertThat(userCreated.getId()).isNotNull();
        }
    }

    @Nested
    class LoadUserByUsernameTests {

        @Test
        void shouldLoadUserByEmailSuccessfully() {
            when(userRepository.findByEmailWithRoles(email)).thenReturn(Optional.of(testUser));

            UserDetails loadedUser = userService.loadUserByUsername(email);

            assertEquals(username, loadedUser.getUsername());
            assertEquals(password, loadedUser.getPassword());
            assertThat(loadedUser.getAuthorities())
                .anyMatch(authority -> authority.getAuthority().equals(roleAdmin.getName().name()));
            verify(userRepository).findByEmailWithRoles(email);
        }

        @Test
        void shouldThrowExceptionWhenUserIsNotFound() {
            when(userRepository.findByEmailWithRoles(email)).thenReturn(Optional.empty());

            UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> userService.loadUserByUsername(email)
            );

            assertThat(exception.getMessage()).contains(email);
            verify(userRepository).findByEmailWithRoles(email);
        }
    }

    @Nested
    class FindUserTests {

        @Test
        void shouldFindUserByEmail() {
            when(userRepository.findByEmail(email)).thenReturn(Optional.of(testUser));

            User foundUser = userService.findUser(email);

            assertSame(testUser, foundUser);
            verify(userRepository).findByEmail(email);
        }

        @Test
        void shouldFindUserByUsername() {
            when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));

            User foundUser = userService.findUser(username);

            assertSame(testUser, foundUser);
            verify(userRepository).findByUsername(username);
        }

        @Test
        void shouldThrowExceptionWhenEmailUserDoesNotExist() {
            when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

            EntityNotFoundException exception = assertThrows(
                EntityNotFoundException.class,
                () -> userService.findUser(email)
            );

            assertThat(exception.getMessage()).contains(email);
            verify(userRepository).findByEmail(email);
        }

        @Test
        void shouldThrowExceptionWhenUsernameUserDoesNotExist() {
            when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

            EntityNotFoundException exception = assertThrows(
                EntityNotFoundException.class,
                () -> userService.findUser(username)
            );

            assertThat(exception.getMessage()).contains(username);
            verify(userRepository).findByUsername(username);
        }

        @Test
        void shouldThrowExceptionWhenUserKeyIsBlank() {
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> userService.findUser("   ")
            );

            assertThat(exception.getMessage()).contains("cannot be empty");
        }
    }

    @Nested
    class ExistsUserTests {

        @Test
        void shouldReturnTrueWhenUserExistsByEmail() {
            when(userRepository.existsByEmail(email)).thenReturn(true);

            boolean exists = userService.existsUser(email);

            assertTrue(exists);
            verify(userRepository).existsByEmail(email);
        }

        @Test
        void shouldReturnFalseWhenUserDoesNotExistByUsername() {
            when(userRepository.existsByUsername(username)).thenReturn(false);

            boolean exists = userService.existsUser(username);

            assertFalse(exists);
            verify(userRepository).existsByUsername(username);
        }

        @Test
        void shouldThrowExceptionWhenUserKeyIsNull() {
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> userService.existsUser(null)
            );

            assertThat(exception.getMessage()).contains("cannot be empty");
        }
    }

    @Nested
    class UpdateUserTests {

        @Test
        void shouldUpdateUserSuccessfully() {
            when(userRepository.save(testUser)).thenReturn(testUser);

            User updatedUser = userService.updateUser(testUser);

            assertSame(testUser, updatedUser);
            verify(userRepository).save(testUser);
        }
    }

    @Nested
    class ChangePasswordTests {

        @Test
        void shouldChangePasswordSuccessfully() {
            User userWithOldPassword = User.builder()
                .username(username)
                .email(email)
                .passwordHash("old_hashed_password")
                .name(name)
                .surname(surname)
                .build();
            userWithOldPassword.setId(UUID.randomUUID());

            User userWithNewPassword = User.builder()
                .username(username)
                .email(email)
                .passwordHash(hashedPassword)
                .name(name)
                .surname(surname)
                .build();
            userWithNewPassword.setId(userWithOldPassword.getId());

            when(passwordSecurityService.matches(newPassword, "old_hashed_password")).thenReturn(false);
            when(passwordSecurityService.encryptPassword(newPassword)).thenReturn(hashedPassword);
            when(userRepository.save(userWithOldPassword)).thenReturn(userWithNewPassword);
            when(passwordSecurityService.matches(newPassword, hashedPassword)).thenReturn(true);

            User updatedUser = userService.changePassword(userWithOldPassword, newPassword);

            assertEquals(hashedPassword, updatedUser.getPasswordHash());
            verify(passwordSecurityService).matches(newPassword, "old_hashed_password");
            verify(passwordSecurityService).encryptPassword(newPassword);
            verify(userRepository, times(1)).save(userWithOldPassword);
            verify(passwordSecurityService).matches(newPassword, hashedPassword);
        }

        @Test
        void shouldFailWhenNewPasswordIsTheSameAsTheCurrentOne() {
            when(passwordSecurityService.matches(newPassword, password)).thenReturn(true);

            InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class,
                () -> userService.changePassword(testUser, newPassword)
            );

            assertThat(exception.getMessage()).contains("different from the existing one");
            verify(passwordSecurityService).matches(newPassword, password);
        }

        @Test
        void shouldFailWhenPersistedPasswordDoesNotMatchExpectedValue() {
            User userWithOldPassword = User.builder()
                .username(username)
                .email(email)
                .passwordHash("old_hashed_password")
                .name(name)
                .surname(surname)
                .build();

            User userWithWrongPersistedPassword = User.builder()
                .username(username)
                .email(email)
                .passwordHash("wrong_hashed_password")
                .name(name)
                .surname(surname)
                .build();

            when(passwordSecurityService.matches(newPassword, "old_hashed_password")).thenReturn(false);
            when(passwordSecurityService.encryptPassword(newPassword)).thenReturn(hashedPassword);
            when(userRepository.save(userWithOldPassword)).thenReturn(userWithWrongPersistedPassword);
            when(passwordSecurityService.matches(newPassword, "wrong_hashed_password")).thenReturn(false);

            InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class,
                () -> userService.changePassword(userWithOldPassword, newPassword)
            );

            assertThat(exception.getMessage()).contains("could not be updated correctly");
            verify(passwordSecurityService).matches(newPassword, "old_hashed_password");
            verify(passwordSecurityService).encryptPassword(newPassword);
            verify(passwordSecurityService).matches(newPassword, "wrong_hashed_password");
        }
    }

    @Nested
    class FindAllUsers {

        @Test
        void shouldReturnAllUsersLoads() {
            when(userRepository.findAllWithRoles()).thenReturn(List.of(testUser, testRoleUser));
            List<UserResponse> allUsers = userService.getAllUsers();
            assertEquals(username, allUsers.get(0).getUsername());
        }

    }

    @Nested
    class UpdateUserRoleTests {

        @Test
        void shouldUpdateUserRoleSuccessfully() {
            UpdateUserRoleRequest updateRoleRequest = UpdateUserRoleRequest.builder()
                .id(testUser.getId().toString())
                .roleName(RoleEnum.ROLE_USER.name())
                .build();

            when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(roleService.findByName(RoleEnum.ROLE_USER)).thenReturn(roleUser);

            UserResponse response = userService.updateUserRole(updateRoleRequest);

            assertEquals(RoleEnum.ROLE_USER.name(), response.getRole());
            assertSame(roleUser, testUser.getRole());
            verify(userRepository).findById(testUser.getId());
            verify(roleService).findByName(RoleEnum.ROLE_USER);
            verify(userRepository).save(testUser);
        }

        @Test
        void shouldThrowWhenUserNotFound() {
            UpdateUserRoleRequest updateRoleRequest = UpdateUserRoleRequest.builder()
                .id(testUser.getId().toString())
                .roleName(RoleEnum.ROLE_USER.name())
                .build();

            when(userRepository.findById(testUser.getId())).thenReturn(Optional.empty());

            assertThrows(
                UserNotFoundException.class,
                () -> userService.updateUserRole(updateRoleRequest)
            );

            verify(userRepository).findById(testUser.getId());
        }
    }

    @Nested
    class VirtualDeleteUserTests {

        @Test
        void shouldDisableUserAndRevokeSessionAndToken() {
            UserSession session = UserSession.builder()
                .user(testUser)
                .revoked(false)
                .build();

            RefreshToken token = RefreshToken.builder()
                .user(testUser)
                .revoked(false)
                .build();

            RefreshToken revokedToken = RefreshToken.builder()
                .user(testUser)
                .revoked(true)
                .build();

            when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(userSessionService.findByUser(testUser)).thenReturn(session);
            when(refreshTokenService.findByUser(testUser)).thenReturn(token);
            when(refreshTokenService.revokeToken(token)).thenReturn(revokedToken);

            UserResponse response = userService.virtualDeleteUser(testUser.getId().toString());

            assertFalse(response.isActive());
            assertFalse(testUser.isEnabled());
            assertTrue(session.isRevoked());
            assertTrue(revokedToken.isRevoked());
            verify(userRepository).findById(testUser.getId());
            verify(userSessionService).findByUser(testUser);
            verify(refreshTokenService).findByUser(testUser);
            verify(refreshTokenService).revokeToken(token);
            verify(userRepository).save(testUser);
        }
    }

    @Nested
    class PermanentlyDeleteUserTests {

        @Test
        void shouldDeleteUserWhenSessionAndTokenDeleted() {
            when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(userSessionService.deleteByUser(testUser)).thenReturn(true);
            when(refreshTokenService.deleteByUser(testUser)).thenReturn(true);

            boolean deleted = userService.permanentlyDeleteUser(testUser.getId().toString());

            assertTrue(deleted);
            verify(userRepository).findById(testUser.getId());
            verify(userSessionService).deleteByUser(testUser);
            verify(refreshTokenService).deleteByUser(testUser);
            verify(userRepository).delete(testUser);
        }
    }

}