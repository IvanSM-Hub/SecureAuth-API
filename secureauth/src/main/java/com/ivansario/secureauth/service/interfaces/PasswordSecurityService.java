package com.ivansario.secureauth.service.interfaces;

import java.security.NoSuchAlgorithmException;

/**
 * Service contract for password hashing and security checks.
 */
public interface PasswordSecurityService {

    /**
     * Validates and hashes the supplied password.
     *
     * @param password raw password
     * @return encoded password hash
     */
    String encryptPassword(String password);

    /**
     * Checks whether a password appears in known public breaches.
     *
     * @param password raw password
     * @return {@code true} when the password is compromised
     */
    boolean isPasswordPwned(String password);

    /**
     * Computes the SHA-1 digest in hexadecimal format.
     *
     * @param input text to hash
     * @return SHA-1 hash in lowercase hex
     * @throws NoSuchAlgorithmException when SHA-1 is unavailable
     */
    String sha1Hex(String input) throws NoSuchAlgorithmException;

    /**
     * Compares a raw password against an encoded hash.
     *
     * @param rawPassword raw password candidate
     * @param hashPassword encoded password hash
     * @return {@code true} when both values match
     */
    boolean matches(String rawPassword, String hashPassword);

}
