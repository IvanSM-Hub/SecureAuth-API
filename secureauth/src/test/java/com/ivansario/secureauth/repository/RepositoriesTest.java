package com.ivansario.secureauth.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.ivansario.secureauth.entity.Permission;
import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.RolePermission;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserRole;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.util.PermissionEnum;
import com.ivansario.secureauth.util.RoleEnum;
import com.ivansario.secureauth.util.RolePermissionId;
import com.ivansario.secureauth.util.UserRoleId;

@DataJpaTest
class RepositoriesTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private RolePermissionRepository rolePermissionRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private UserSessionRepository userSessionRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @TestConfiguration
    static class TestConfig {
        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }

    @Test
    public void testUserRepository() {
        
        // Arrange
        String passwordPlana = "passwordtest";
        User user = User.builder()
        .username("usertest")
        .name("nametest")
        .surname("surnametest")
        .email("test@email.com")
        .passwordHash(passwordEncoder.encode(passwordPlana))
        .build();

        // Act
        User userSaved = userRepository.save(user);
        User usuarioBuscado = userRepository.findByEmail("test@email.com").orElse(null);

        // Assert
        assertThat(usuarioBuscado).isNotNull();
        assertThat(userSaved.getId()).isNotNull();
        assertThat(usuarioBuscado.getUsername()).isEqualTo(user.getUsername());
        assertThat(usuarioBuscado.getEmail()).isEqualTo(user.getEmail());
        assertThat(usuarioBuscado.getSurname()).isEqualTo("surnametest");
        assertThat(usuarioBuscado.getPasswordHash()).isNotEqualTo(passwordPlana);
        assertThat(passwordEncoder.matches(passwordPlana, usuarioBuscado.getPasswordHash())).isTrue();
        assertThat(usuarioBuscado).usingRecursiveComparison()
                                .ignoringFields("id") 
                                .isEqualTo(user);
        assertThat(userSaved).isEqualTo(usuarioBuscado);

    }

    @Test
    public void testPermissionRepository() {
        
        // Arrange
        Permission permission = Permission.builder()
        .name(PermissionEnum.PERMISSION_CREATE)
        .description("Permiso para crear usuarios")
        .build();

        // Act
        Permission permissionSaved = permissionRepository.save(permission);
        Optional<Permission> permissionBuscado = permissionRepository.findByName(PermissionEnum.PERMISSION_CREATE);
        boolean exists = permissionRepository.existsByName(PermissionEnum.PERMISSION_CREATE);

        // Assert
        assertThat(permissionBuscado).isPresent();
        assertThat(permissionSaved.getId()).isNotNull();
        assertThat(permissionBuscado.get().getName()).isEqualTo(permission.getName());
        assertThat(permissionBuscado.get().getDescription()).isEqualTo("Permiso para crear usuarios");
        assertThat(exists).isTrue();
        assertThat(permissionBuscado.get()).usingRecursiveComparison()
                                         .ignoringFields("id")
                                         .isEqualTo(permission);
        assertThat(permissionSaved).isEqualTo(permissionBuscado.get());

    }

    @Test
    public void testRoleRepository() {
        
        // Arrange
        Role role = Role.builder()
        .name(RoleEnum.ROLE_ADMIN)
        .description("Administrador del sistema")
        .build();

        // Act
        Role roleSaved = roleRepository.save(role);
        Optional<Role> roleBuscado = roleRepository.findByName(RoleEnum.ROLE_ADMIN);
        boolean exists = roleRepository.existsByName(RoleEnum.ROLE_ADMIN);

        // Assert
        assertThat(roleBuscado).isPresent();
        assertThat(roleSaved.getId()).isNotNull();
        assertThat(roleBuscado.get().getName()).isEqualTo(role.getName());
        assertThat(roleBuscado.get().getDescription()).isEqualTo("Administrador del sistema");
        assertThat(exists).isTrue();
        assertThat(roleBuscado.get()).usingRecursiveComparison()
                                    .ignoringFields("id")
                                    .isEqualTo(role);
        assertThat(roleSaved).isEqualTo(roleBuscado.get());

    }

    @Test
    public void testRefreshTokenRepository() {
        
        // Arrange
        String passwordPlana = "passwordtest";
        User user = User.builder()
        .username("usertest")
        .name("nametest")
        .surname("surnametest")
        .email("test@email.com")
        .passwordHash(passwordEncoder.encode(passwordPlana))
        .build();
        User userSaved = userRepository.save(user);

        RefreshToken refreshToken = RefreshToken.builder()
        .user(userSaved)
        .token("testtoken123456789")
        .ipAddress("127.0.0.1")
        .userAgent("Mozilla/5.0")
        .build();

        // Act
        RefreshToken refreshTokenSaved = refreshTokenRepository.save(refreshToken);
        Optional<RefreshToken> refreshTokenBuscado = refreshTokenRepository.findByToken("testtoken123456789");
        List<RefreshToken> tokensPorUsuario = refreshTokenRepository.findAllByUser(userSaved);

        // Assert
        assertThat(refreshTokenBuscado).isPresent();
        assertThat(refreshTokenSaved.getId()).isNotNull();
        assertThat(refreshTokenBuscado.get().getToken()).isEqualTo("testtoken123456789");
        assertThat(refreshTokenBuscado.get().getUser()).isEqualTo(userSaved);
        assertThat(refreshTokenBuscado.get().getIpAddress()).isEqualTo("127.0.0.1");
        assertThat(refreshTokenBuscado.get().isRevoked()).isFalse();
        assertThat(tokensPorUsuario).isNotEmpty();
        assertThat(tokensPorUsuario).contains(refreshTokenSaved);

    }

    @Test
    public void testRolePermissionRepository() {
        
        // Arrange
        Role role = Role.builder()
        .name(RoleEnum.ROLE_ADMIN)
        .description("Administrador del sistema")
        .build();
        Role roleSaved = roleRepository.save(role);

        Permission permission = Permission.builder()
        .name(PermissionEnum.PERMISSION_CREATE)
        .description("Permiso para crear usuarios")
        .build();
        Permission permissionSaved = permissionRepository.save(permission);

        RolePermissionId rolePermissionId = new RolePermissionId(roleSaved.getId(), permissionSaved.getId());
        RolePermission rolePermission = RolePermission.builder()
        .id(rolePermissionId)
        .role(roleSaved)
        .permission(permissionSaved)
        .build();

        // Act
        RolePermission rolePermissionSaved = rolePermissionRepository.save(rolePermission);
        List<RolePermission> permisosPorRole = rolePermissionRepository.findAllByRole(roleSaved);
        boolean exists = rolePermissionRepository.existsByRoleAndPermission(roleSaved, permissionSaved);

        // Assert
        assertThat(rolePermissionSaved.getRole()).isEqualTo(roleSaved);
        assertThat(rolePermissionSaved.getPermission()).isEqualTo(permissionSaved);
        assertThat(permisosPorRole).isNotEmpty();
        assertThat(permisosPorRole).contains(rolePermissionSaved);
        assertThat(exists).isTrue();

    }

    @Test
    public void testUserRoleRepository() {
        
        // Arrange
        String passwordPlana = "passwordtest";
        User user = User.builder()
        .username("usertest")
        .name("nametest")
        .surname("surnametest")
        .email("test@email.com")
        .passwordHash(passwordEncoder.encode(passwordPlana))
        .build();
        User userSaved = userRepository.save(user);

        Role role = Role.builder()
        .name(RoleEnum.ROLE_ADMIN)
        .description("Administrador del sistema")
        .build();
        Role roleSaved = roleRepository.save(role);

        UserRoleId userRoleId = new UserRoleId(userSaved.getId(), roleSaved.getId());
        UserRole userRole = new UserRole();
        userRole.setId(userRoleId);
        userRole.setUser(userSaved);
        userRole.setRole(roleSaved);

        // Act
        UserRole userRoleSaved = userRoleRepository.save(userRole);
        List<UserRole> rolesPorUsuario = userRoleRepository.findAllByUser(userSaved);
        boolean exists = userRoleRepository.existsByUserAndRole(userSaved, roleSaved);

        // Assert
        assertThat(userRoleSaved.getId()).isNotNull();
        assertThat(userRoleSaved.getUser()).isEqualTo(userSaved);
        assertThat(userRoleSaved.getRole()).isEqualTo(roleSaved);
        assertThat(rolesPorUsuario).isNotEmpty();
        assertThat(rolesPorUsuario).contains(userRoleSaved);
        assertThat(exists).isTrue();

    }

    @Test
    public void testUserSessionRepository() {
        
        // Arrange
        String passwordPlana = "passwordtest";
        User user = User.builder()
        .username("usertest")
        .name("nametest")
        .surname("surnametest")
        .email("test@email.com")
        .passwordHash(passwordEncoder.encode(passwordPlana))
        .build();
        User userSaved = userRepository.save(user);

        RefreshToken refreshToken = RefreshToken.builder()
        .user(userSaved)
        .token("testtoken123456789")
        .ipAddress("127.0.0.1")
        .userAgent("Mozilla/5.0")
        .build();
        RefreshToken refreshTokenSaved = refreshTokenRepository.save(refreshToken);

        UserSession userSession = UserSession.builder()
        .user(userSaved)
        .refreshToken(refreshTokenSaved)
        .ipAddress("192.168.1.1")
        .deviceInfo("Desktop - Chrome")
        .build();

        // Act
        UserSession userSessionSaved = userSessionRepository.save(userSession);
        List<UserSession> sessionesPorUsuario = userSessionRepository.findAllByUser(userSaved);
        Optional<UserSession> sessionPorToken = userSessionRepository.findByRefreshToken(refreshTokenSaved);

        // Assert
        assertThat(userSessionSaved.getId()).isNotNull();
        assertThat(userSessionSaved.getUser()).isEqualTo(userSaved);
        assertThat(userSessionSaved.getRefreshToken()).isEqualTo(refreshTokenSaved);
        assertThat(userSessionSaved.getIpAddress()).isEqualTo("192.168.1.1");
        assertThat(userSessionSaved.isRevoked()).isFalse();
        assertThat(sessionesPorUsuario).isNotEmpty();
        assertThat(sessionesPorUsuario).contains(userSessionSaved);
        assertThat(sessionPorToken).isPresent();
        assertThat(sessionPorToken.get()).isEqualTo(userSessionSaved);

    }
    
}
