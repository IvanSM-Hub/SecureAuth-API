package com.ivansario.secureauth.dto;

import java.util.List;

import com.ivansario.secureauth.util.RoleEnum;

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
    private Long id;
    private String username;
    private String email;
    private List<RoleEnum> role;
    private String accessToken;
    private String refreshToken;
}
