package com.ivansario.secureauth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.ivansario.secureauth.exception.InvalidPasswordProvided;
import com.ivansario.secureauth.service.interfaces.ObviousPasswordService;
import com.ivansario.secureauth.service.interfaces.PasswordSecurityService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class PasswordSecurityServiceImpl implements PasswordSecurityService {

    private final PasswordEncoder passwordEncoder;
    private final ObviousPasswordService obvPassService;
    private final RestTemplate restTemplate;

    @Override
    public String encryptPassword(String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new InvalidPasswordProvided("Password cannot be empty");
        }

        if (rawPassword.contains(" ")) {
            throw new InvalidPasswordProvided("Password cannot have spaces");
        }

        String candidate = rawPassword.trim();

        if (!obvPassService.isValidPassword(candidate)) {
            throw new InvalidPasswordProvided("Password is too common or obvious");
        }

        if (isPasswordPwned(candidate)) {
            throw new InvalidPasswordProvided("Password has been exposed in known breaches");
        }        
        return passwordEncoder.encode(candidate);
    }

    @Override
    public boolean isPasswordPwned(String rawPassword) {
        String sha1;
        try {
            sha1 = sha1Hex(rawPassword).toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidPasswordProvided("Error trying to calculate password hash.", e);
        }

        String prefix = sha1.substring(0, 5);
        String suffix = sha1.substring(5);
        String url = "https://api.pwnedpasswords.com/range/" + prefix;

        String response;
        try {
            response = restTemplate.getForObject(url, String.class);
        } catch (RestClientException e) {
            log.warn("HIBP lookup unavailable for prefix {}. Continuing without breach validation.", prefix, e);
            return false;
        }

        if (response == null || response.isBlank()) {
            return false;
        }

        for (String line : response.split("\\r?\\n")) {
            String[] parts = line.split(":");
            if (parts.length < 2) {
                continue;
            }

            if (parts[0].equalsIgnoreCase(suffix)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public String sha1Hex(String input) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] digest = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public boolean matches(String rawPassword, String hashPassword) {
        return passwordEncoder.matches(rawPassword, hashPassword);
    }

}
