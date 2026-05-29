package com.ivansario.secureauth.service.interfaces;

import java.security.NoSuchAlgorithmException;

public interface PasswordSecurityService {

    String encryptPassword(String password);
    boolean isPasswordPwned(String password);
    String sha1Hex(String input) throws NoSuchAlgorithmException;
    boolean matches(String rawPassword, String hashPassword);

}
