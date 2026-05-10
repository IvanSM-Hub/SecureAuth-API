package com.ivansario.secureauth.service;

import java.util.UUID;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.repository.UserRepository;
import com.ivansario.secureauth.service.interfaces.UserService;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository
        .findByEmail(email)
        .orElseThrow(
            () -> new UsernameNotFoundException("Usuario no encontrado: " + email)
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
        .build();

        return userRepository.save(user);

    }

    @Override
    public User changePassword(NewPasswordUserRequest newPassword) {
        throw new UnsupportedOperationException("Unimplemented method 'changePassword'");
    }

    @Override
    public User deleteUser(UUID id) {
        throw new UnsupportedOperationException("Unimplemented method 'deleteUser'");
    }

    @Override
    public User updateUser(User user) {
        return userRepository.save(user);
    }
    
    @Override
    public User findUser(String userKey) {
        validateUserKey(userKey);

        return (userKey.contains("@")
                ? userRepository.findByEmail(userKey)
                : userRepository.findByUsername(userKey))
                .orElseThrow(() -> {
                    log.error("Usuario no encontrado en la base de datos: {}", userKey);
                    return new EntityNotFoundException("No se encontró el usuario: " + userKey);
                });
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    @Override
    public String toString() {
        return super.toString();
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
            log.warn("Se intentó buscar un usuario con una clave nula o vacía");
            throw new IllegalArgumentException("La clave de búsqueda no puede estar vacía");
        }
    }

}
