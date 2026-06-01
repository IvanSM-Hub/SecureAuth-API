package com.ivansario.secureauth.dto;

import jakarta.validation.constraints.NotBlank;
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
public class InitialAdminLoginRequest {

    @NotBlank(message = "Password is required")
    private String password;

    @NotBlank(message = "Username is required")
    private String username;

}
