package com.ivansario.secureauth.dto.user;

import java.time.LocalDateTime;

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
@Schema(description = "User profile returned by the users endpoints")
public class UserResponse {

    @Schema(description = "Username", example = "ivan.sario")
    private String username;
    @Schema(description = "Email address", example = "ivan@example.com")
    private String email;
    @Schema(description = "Assigned role", example = "ROLE_ADMIN")
    private String role;
    @Schema(description = "Concatenated full name", example = "Ivan Sario")
    private String completeName;
    @Schema(description = "Creation timestamp", example = "2026-05-27T10:15:30")
    private LocalDateTime createdAt;
    @Schema(description = "Last update timestamp", example = "2026-05-27T12:15:30")
    private LocalDateTime updatedAt;
    @Schema(description = "Last login timestamp", example = "2026-05-27T12:45:30")
    private LocalDateTime lastLogin;
    @Schema(description = "Whether the user is active", example = "true")
    private boolean isActive;

    public static String generateCompleteName(String firstName, String lastName) {
        String name = firstName == null ? "" : firstName.trim();
        String surname = lastName == null ? "" : lastName.trim();
        String combined = (name + " " + surname).trim();
        return combined.isEmpty() ? null : combined;
    }
    
}
