package com.ivansario.secureauth.dto.protect;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
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
@Schema(description = "Request payload containing an obvious-password entry id")
public class ObviousPasswordIdRequest {

    @NotBlank(message = "Obvious password id is required")
    @Pattern(
        regexp = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        message = "Obvious password id must be a valid UUID"
    )
    @Schema(description = "Obvious password entry identifier (UUID)", example = "7f84a249-f0f6-4cf8-a464-82f6fd4aab8f")
    private String id;

}
