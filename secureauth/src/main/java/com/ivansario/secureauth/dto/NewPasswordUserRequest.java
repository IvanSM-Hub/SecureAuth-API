package com.ivansario.secureauth.dto;

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

    @NotBlank(message = "El refresh token no puede estar vacío")
    @Size(min = 20, max = 500, message = "El token no tiene el formato correcto")
    private String token;

    @NotBlank(message = "La nueva contraseña es obligatoria")
    @Size(min = 8, max = 255, message = "La contraseña debe tener entre 8 y 255 caracteres")
    private String newPassword;

    @NotBlank(message = "La confirmación de contraseña es obligatoria")
    @Size(min = 8, max = 255, message = "La confirmación debe tener entre 8 y 255 caracteres")
    private String confirmPassword;

}
