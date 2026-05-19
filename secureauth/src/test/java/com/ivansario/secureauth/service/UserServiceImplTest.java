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
import org.springframework.security.crypto.password.PasswordEncoder;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.exception.InvalidCredentialsException;
import com.ivansario.secureauth.repository.UserRepository;
import com.ivansario.secureauth.util.RoleEnum;

import jakarta.persistence.EntityNotFoundException;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImpl userService;

    private User testUser;
    private CreateUserRequest createUserRequest;
    private Role roleAdmin;

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
    }

    @Nested
    class CreateUserTests {

        @Test
        void shouldCreateUserSuccessfully() {
            UUID generatedId = UUID.randomUUID();

            when(passwordEncoder.encode(password)).thenReturn(hashedPassword);
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
            assertEquals(generatedId, userCreated.getId());
            verify(passwordEncoder).encode(password);
            verify(userRepository).save(any(User.class));
            assertThat(userCreated.getId()).isNotNull();
        }
    }

    @Nested
    class LoadUserByUsernameTests {

        @Test
        void shouldLoadUserByEmailSuccessfully() {
            when(userRepository.findByEmail(email)).thenReturn(Optional.of(testUser));

            UserDetails loadedUser = userService.loadUserByUsername(email);

            assertSame(testUser, loadedUser);
            verify(userRepository).findByEmail(email);
        }

        @Test
        void shouldThrowExceptionWhenUserIsNotFound() {
            when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

            UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> userService.loadUserByUsername(email)
            );

            assertThat(exception.getMessage()).contains(email);
            verify(userRepository).findByEmail(email);
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

            assertThat(exception.getMessage()).contains("vacía");
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

            assertThat(exception.getMessage()).contains("vacía");
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

            when(passwordEncoder.matches(newPassword, "old_hashed_password")).thenReturn(false);
            when(passwordEncoder.encode(newPassword)).thenReturn(hashedPassword);
            when(userRepository.save(userWithOldPassword)).thenReturn(userWithNewPassword);
            when(passwordEncoder.matches(newPassword, hashedPassword)).thenReturn(true);

            User updatedUser = userService.changePassword(userWithOldPassword, newPassword);

            assertEquals(hashedPassword, updatedUser.getPasswordHash());
            verify(passwordEncoder).matches(newPassword, "old_hashed_password");
            verify(passwordEncoder).encode(newPassword);
            verify(userRepository, times(2)).save(userWithOldPassword);
            verify(passwordEncoder).matches(newPassword, hashedPassword);
        }

        @Test
        void shouldFailWhenNewPasswordIsTheSameAsTheCurrentOne() {
            when(passwordEncoder.matches(newPassword, password)).thenReturn(true);

            InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class,
                () -> userService.changePassword(testUser, newPassword)
            );

            assertThat(exception.getMessage()).contains("distinta");
            verify(passwordEncoder).matches(newPassword, password);
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

            when(passwordEncoder.matches(newPassword, "old_hashed_password")).thenReturn(false);
            when(passwordEncoder.encode(newPassword)).thenReturn(hashedPassword);
            when(userRepository.save(userWithOldPassword)).thenReturn(userWithWrongPersistedPassword);
            when(passwordEncoder.matches(newPassword, "wrong_hashed_password")).thenReturn(false);

            InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class,
                () -> userService.changePassword(userWithOldPassword, newPassword)
            );

            assertThat(exception.getMessage()).contains("No se ha podido actualizar");
            verify(passwordEncoder).matches(newPassword, "old_hashed_password");
            verify(passwordEncoder).encode(newPassword);
            verify(passwordEncoder).matches(newPassword, "wrong_hashed_password");
        }
    }
}