package com.ivansario.secureauth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserRole;
import com.ivansario.secureauth.repository.UserRoleRepository;
import com.ivansario.secureauth.util.RoleEnum;

@ExtendWith(MockitoExtension.class)
class UserRoleServiceImplTest {

    @Mock
    private UserRoleRepository userRoleRepository;

    @InjectMocks
    private UserRoleServiceImpl userRoleService;

    private User user;
    private Role roleAdmin;
    private Role roleUser;

    private final String email = "test@email.com";
    private final String username = "usernametest";
    private final String name = "Name";
    private final String surname = "Surname";

    @BeforeEach
    void setUp() {
        user = User.builder()
            .username(username)
            .email(email)
            .passwordHash("password_hash")
            .name(name)
            .surname(surname)
            .build();
        user.setId(UUID.randomUUID());

        roleAdmin = Role.builder()
            .name(RoleEnum.ROLE_ADMIN)
            .description("Full system access with all permissions")
            .build();
        roleAdmin.setId(UUID.randomUUID());

        roleUser = Role.builder()
            .name(RoleEnum.ROLE_USER)
            .description("Standard user with limited permissions")
            .build();
        roleUser.setId(UUID.randomUUID());
    }

    @Nested
    class FindAllTests {

        @Test
        void shouldThrowUnsupportedOperationException() {
            UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> userRoleService.findAll()
            );

            assertThat(exception.getMessage()).contains("Not implemented");
        }
    }

    @Nested
    class FindByIdTests {

        @Test
        void shouldThrowUnsupportedOperationException() {
            UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> userRoleService.findById(UUID.randomUUID())
            );

            assertThat(exception.getMessage()).contains("Not implemented");
        }
    }

    @Nested
    class CreateTests {

        @Test
        void shouldCreateUserRoleSuccessfully() {
            when(userRoleRepository.save(any(UserRole.class))).thenAnswer(invocation -> invocation.getArgument(0));

            UserRole created = userRoleService.create(user, roleAdmin);

            assertNotNull(created);
            assertSame(user, created.getUser());
            assertSame(roleAdmin, created.getRole());
            assertNotNull(created.getId());
            assertEquals(user.getId(), created.getId().getUserId());
            assertEquals(roleAdmin.getId(), created.getId().getRoleId());
            assertThat(created.getAssignedAt()).isNotNull();
            verify(userRoleRepository).save(any(UserRole.class));
        }

        @Test
        void shouldCreateUserRoleWithCorrectCompositeKey() {
            when(userRoleRepository.save(any(UserRole.class))).thenAnswer(invocation -> invocation.getArgument(0));

            UserRole created = userRoleService.create(user, roleAdmin);

            assertThat(created.getId().getUserId()).isEqualTo(user.getId());
            assertThat(created.getId().getRoleId()).isEqualTo(roleAdmin.getId());
            verify(userRoleRepository).save(any(UserRole.class));
        }

        @Test
        void shouldCreateMultipleUserRolesForSameUserDifferentRoles() {
            when(userRoleRepository.save(any(UserRole.class))).thenAnswer(invocation -> invocation.getArgument(0));

            UserRole firstUserRole = userRoleService.create(user, roleAdmin);
            UserRole secondUserRole = userRoleService.create(user, roleUser);

            assertSame(user, firstUserRole.getUser());
            assertSame(user, secondUserRole.getUser());
            assertSame(roleAdmin, firstUserRole.getRole());
            assertSame(roleUser, secondUserRole.getRole());
            assertNotEquals(firstUserRole.getId().getRoleId(), secondUserRole.getId().getRoleId());
        }

        @Test
        void shouldSetAssignedAtTimestamp() {
            LocalDateTime beforeCreation = LocalDateTime.now();
            when(userRoleRepository.save(any(UserRole.class))).thenAnswer(invocation -> invocation.getArgument(0));

            UserRole created = userRoleService.create(user, roleAdmin);

            assertThat(created.getAssignedAt()).isAfterOrEqualTo(beforeCreation);
            assertThat(created.getAssignedAt()).isBeforeOrEqualTo(LocalDateTime.now().plusSeconds(1));
        }
    }

    @Nested
    class UpdateTests {

        @Test
        void shouldThrowUnsupportedOperationException() {
            UserRole userRole = new UserRole();
            userRole.setUser(user);
            userRole.setRole(roleAdmin);

            UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> userRoleService.update(userRole)
            );

            assertThat(exception.getMessage()).contains("Not implemented");
        }
    }

    @Nested
    class DeleteTests {

        @Test
        void shouldThrowUnsupportedOperationException() {
            UnsupportedOperationException exception = assertThrows(
                UnsupportedOperationException.class,
                () -> userRoleService.delete(UUID.randomUUID())
            );

            assertThat(exception.getMessage()).contains("Not implemented");
        }
    }
}
