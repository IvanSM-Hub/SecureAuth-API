package com.ivansario.secureauth.service;

import java.util.UUID;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.UpdateUserRequest;
import com.ivansario.secureauth.dto.UserResponse;
import com.ivansario.secureauth.repository.UserRepository;
import com.ivansario.secureauth.service.interfaces.UserService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository
        .findByEmail(email)
        .orElseThrow(
            () -> new UsernameNotFoundException("Usuario no encontrado: " + email)
        );
    }

    @Override
    public UserResponse createUser(CreateUserRequest createUserRequest) {
        throw new UnsupportedOperationException("Unimplemented method 'createUser'");
    }

    @Override
    public UserResponse changePassword(NewPasswordUserRequest newPassword) {
        throw new UnsupportedOperationException("Unimplemented method 'changePassword'");
    }

    @Override
    public UserResponse deleteUser(UUID id) {
        throw new UnsupportedOperationException("Unimplemented method 'deleteUser'");
    }

    @Override
    public UserResponse updateUser(UpdateUserRequest updateUser) {
        return null;
    }
    
    @Override
    public UserResponse findUser() {
        return null;
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

}
