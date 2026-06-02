package com.ivansario.secureauth.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
public class NewPasswordUserRequest {

    @NotBlank(message = "Refresh token cannot be blank")
    @Size(min = 20, max = 500, message = "The token has an invalid format")
    private String token;

    @NotBlank(message = "Current password is required")
    @Size(min = 8, max = 255, message = "Current password must be between 8 and 255 characters")
    private String currentPassword;

    @NotBlank(message = "New password is required")
    @Size(min = 8, max = 255, message = "Password must be between 8 and 255 characters")
    private String newPassword;

    @NotBlank(message = "Password confirmation is required")
    @Size(min = 8, max = 255, message = "Confirmation must be between 8 and 255 characters")
    private String confirmPassword;

}
