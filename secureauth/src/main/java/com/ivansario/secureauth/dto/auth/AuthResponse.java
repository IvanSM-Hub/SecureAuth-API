package com.ivansario.secureauth.dto.auth;

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
@Schema(description = "Authentication response containing profile data and JWT tokens")
public class AuthResponse {
    @Schema(description = "Authenticated username", example = "ivan.sario")
    private String username;
    @Schema(description = "User email", example = "ivan@example.com")
    private String email;
    @Schema(description = "Assigned role", example = "ROLE_USER")
    private String role;
    @Schema(description = "JWT access token")
    private String accessToken;
    @Schema(description = "JWT refresh token")
    private String refreshToken;
}
