package com.ivansario.secureauth.dto.protect;

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
public class ProtectionUsernameRequest {

    @NotBlank(message = "The username is required")
    private String username;

}
