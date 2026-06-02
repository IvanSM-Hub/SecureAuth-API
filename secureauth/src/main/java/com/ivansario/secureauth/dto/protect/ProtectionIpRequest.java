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
public class ProtectionIpRequest {

    @NotBlank(message = "The ip is required")
    private String ip;

}
