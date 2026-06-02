package com.ivansario.secureauth.dto.protect;

import com.ivansario.secureauth.entity.Role;

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
@Schema(description = "Response returned by user and IP protection endpoints")
public class ProtectionResponse {

    @Schema(description = "Origin IP address associated with the protection record", example = "192.168.1.10")
    private String ip;
    @Schema(description = "Number of failed authentication attempts recorded", example = "3")
    private int numTrys;
    @Schema(description = "Date and time of the last failed attempt", example = "2026-06-02T14:30:00")
    private String lastTry;
    @Schema(description = "Date and time until the user or IP remains blocked", example = "2026-06-02T14:45:00")
    private String bloquedAt;
    @Schema(description = "Whether the protection block is currently active", example = "true")
    private boolean active;
    @Schema(description = "Registered username", example = "ivan.sario")
    private String username;
    @Schema(description = "Registered email address", example = "ivan.sario@example.com")
    private String email;
    @Schema(description = "Whether the user account is enabled", example = "true")
    private boolean enable;
    @Schema(description = "Date and time when the user account was created", example = "2026-05-20T09:00:00")
    private String createAt;
    @Schema(description = "Date and time of the last account update", example = "2026-06-01T18:20:00")
    private String updatedAt;
    @Schema(description = "Date and time of the last successful login", example = "2026-06-02T08:15:00")
    private String lastLogin;
    @Schema(description = "Role assigned to the user")
    private Role role;

}
