package com.ivansario.secureauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
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
@Schema(description = "Response returned after registering a new user")
public class RegisterResponse {

    @Schema(description = "Registered username", example = "ivan.sario")
    private String username;
    @Schema(description = "Registered email", example = "ivan@example.com")
    private String email;
    @Schema(description = "Assigned role", example = "ROLE_USER")
    private String role;

}
