package com.ivansario.secureauth.dto;

import java.util.Set;

import com.ivansario.secureauth.entity.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponse {
    private String username;
    private String email;
    private Set<Role> role;
    private String accessToken;
    private String refreshToken;
}
