package com.ivansario.secureauth.dto;

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

    private String email;
    private String username;
    private String newPassword;
    private String confirmPassword;

}
