package com.ivansario.secureauth.service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Service;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.ivansario.secureauth.dto.protect.ProtectionIpRequest;
import com.ivansario.secureauth.dto.protect.ProtectionResponse;
import com.ivansario.secureauth.dto.protect.ProtectionUsernameRequest;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserProtection;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.exception.UserProtectionException;
import com.ivansario.secureauth.repository.UserProtectionRepository;
import com.ivansario.secureauth.service.interfaces.UserProtectionService;
import com.ivansario.secureauth.service.interfaces.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserProtectionServiceImpl implements UserProtectionService {

    private static final String INVALID_INPUT_MESSAGE = "The provided value is invalid";

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration BLOCK_DURATION = Duration.ofMinutes(15);
    private static final String IP_TRIES_KEY = "protect:ip:tries:";
    private static final String USER_TRIES_KEY = "protect:user:tries:";
    private static final String IP_BLOCK_KEY = "protect:ip:block:";
    private static final String USER_BLOCK_KEY = "protect:user:block:";

    private final UserProtectionRepository userProtectionRepository;
    private final UserService userService;
    private final StringRedisTemplate redisTemplate;

    @Override
    public void blockIp(String ip, Duration duration) {
        if (ip == null || ip.isBlank() || (duration != null && duration.isNegative())) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedIp = ip.trim();
        Duration effectiveDuration = duration != null ? duration : BLOCK_DURATION;
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime blockedAt = now.plus(effectiveDuration);

        updateRedisBlock(ipBlockKey(normalizedIp), ipTriesKey(normalizedIp), effectiveDuration);

        UserProtection protection = userProtectionRepository.findByIpOrigin(normalizedIp)
            .orElseGet(() -> buildIpProtection(normalizedIp, now));

        applyBlock(protection, blockedAt, false);
    }

    @Override
    public void blockUser(String username, Duration duration) {
        if (username == null || username.isBlank() || (duration != null && duration.isNegative())) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedUsername = username.trim();
        Duration effectiveDuration = duration != null ? duration : BLOCK_DURATION;
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime blockedAt = now.plus(effectiveDuration);

        updateRedisBlock(userBlockKey(normalizedUsername), userTriesKey(normalizedUsername), effectiveDuration);

        UserProtection protection = userProtectionRepository.findByUser_Username(normalizedUsername)
            .orElseGet(() -> buildUserProtection(normalizedUsername, "User: " + normalizedUsername, now));

        applyBlock(protection, blockedAt, false);
    }

    @Override
    public Optional<Instant> getBlockedUntilForIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedIp = ip.trim();
        Optional<Instant> blockedByRedis = getBlockedUntilFromRedis(ipBlockKey(normalizedIp));
        if (blockedByRedis.isPresent()) {
            return blockedByRedis;
        }

        return getBlockedUntil(userProtectionRepository.findByIpOrigin(normalizedIp));
    }

    @Override
    public Optional<Instant> getBlockedUntilForUser(String username) {
        if (username == null || username.isEmpty()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedUsername = username.trim();
        Optional<Instant> blockedByRedis = getBlockedUntilFromRedis(userBlockKey(normalizedUsername));
        if (blockedByRedis.isPresent()) {
            return blockedByRedis;
        }

        return getBlockedUntil(userProtectionRepository.findByUser_Username(normalizedUsername));
    }

    @Override
    public int getFailedAttemptsForIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedIp = ip.trim();
        Integer redisAttempts = getAttemptsFromRedis(ipTriesKey(normalizedIp));
        if (redisAttempts != null) {
            return redisAttempts;
        }

        return userProtectionRepository.findByIpOrigin(normalizedIp)
            .map(UserProtection::getNumTrys)
            .orElse(0);
    }

    @Override
    public int getFailedAttemptsForUser(String username) {
        if (username == null || username.isEmpty()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedUsername = username.trim();
        Integer redisAttempts = getAttemptsFromRedis(userTriesKey(normalizedUsername));
        if (redisAttempts != null) {
            return redisAttempts;
        }

        return userProtectionRepository.findByUser_Username(normalizedUsername)
            .map(UserProtection::getNumTrys)
            .orElse(0);
    }

    @Override
    public boolean isBlocked(String username, String ip) {
        return isIpBlocked(ip) || isUserBlocked(username);
    }

    @Override
    public boolean isIpBlocked(String ip) {
        if (ip == null || ip.isEmpty()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedIp = ip.trim();
        if (isBlockedInRedis(ipBlockKey(normalizedIp))) {
            return true;
        }

        Optional<UserProtection> userProtection = userProtectionRepository.findByIpOrigin(normalizedIp);
        if (userProtection.isEmpty()) {
            return false;
        }

        UserProtection protection = userProtection.get();
        LocalDateTime blockedAt = protection.getBloquedAt();
        if (blockedAt == null) {
            protection.setActive(false);
            return false;
        }

        boolean blocked = blockedAt.isAfter(LocalDateTime.now());
        protection.setActive(blocked);
        return blocked;
    }

    @Override
    public boolean isUserBlocked(String username) {
        if (username == null || username.isEmpty()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedUsername = username.trim();
        if (isBlockedInRedis(userBlockKey(normalizedUsername))) {
            return true;
        }

        Optional<UserProtection> userProtection = userProtectionRepository.findByUser_Username(normalizedUsername);
        if (userProtection.isEmpty()) {
            return false;
        }

        UserProtection protection = userProtection.get();
        LocalDateTime blockedAt = protection.getBloquedAt();
        if (blockedAt == null) {
            protection.setActive(false);
            return false;
        }

        boolean blocked = blockedAt.isAfter(LocalDateTime.now());
        protection.setActive(blocked);
        return blocked;
    }

    @Override
    public void registerFailedAttempt(String username, String ip) {
        if (username == null || username.isBlank() || ip == null || ip.isBlank()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedIp = ip.trim();
        String normalizedUsername = username.trim();
        LocalDateTime now = LocalDateTime.now();

        if (isBlocked(normalizedUsername, normalizedIp)) {
            return;
        }

        registerFailedAttemptInRedis(normalizedUsername, normalizedIp);

        UserProtection ipProtection = userProtectionRepository.findByIpOrigin(normalizedIp)
            .orElseGet(() -> buildIpProtection(normalizedIp, now));
        UserProtection userProtection = userProtectionRepository.findByUser_Username(normalizedUsername)
            .orElseGet(() -> buildUserProtection(normalizedUsername, normalizedIp, now));

        registerFailedAttemptOnProtection(ipProtection, now);
        registerFailedAttemptOnProtection(userProtection, now);

        userProtectionRepository.save(ipProtection);
        userProtectionRepository.save(userProtection);
    }

    private void registerFailedAttemptOnProtection(UserProtection protection, LocalDateTime now) {
        int tries = protection.getNumTrys() + 1;
        protection.setNumTrys(tries);
        protection.setLastTry(now);

        if (tries >= MAX_FAILED_ATTEMPTS) {
            protection.setBloquedAt(now.plus(BLOCK_DURATION));
            protection.setActive(true);
            return;
        }

        protection.setBloquedAt(null);
        protection.setActive(false);
    }

    @Override
    public void registerSuccessfulLogin(String username, String ip) {
        if ((ip == null || ip.isBlank()) && (username == null || username.isBlank())) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        LocalDateTime now = LocalDateTime.now();
        String normalizedIp = ip == null ? null : ip.trim();
        String normalizedUsername = username == null ? null : username.trim();

        if (normalizedIp != null && !normalizedIp.isBlank()) {
            clearProtectionInRedis(null, normalizedIp);
            userProtectionRepository.findByIpOrigin(normalizedIp)
                .ifPresent(protection -> resetProtection(protection, now));
        }

        if (normalizedUsername != null && !normalizedUsername.isBlank()) {
            clearProtectionInRedis(normalizedUsername, null);
            userProtectionRepository.findByUser_Username(normalizedUsername)
                .ifPresent(protection -> resetProtection(protection, now));
        }
    }

    @Override
    public void resetFailedAttempts(String username, String ip) {
        if ((ip == null || ip.isBlank()) && (username == null || username.isBlank())) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        LocalDateTime now = LocalDateTime.now();
        String normalizedIp = ip == null ? null : ip.trim();
        String normalizedUsername = username == null ? null : username.trim();

        if (normalizedIp != null && !normalizedIp.isBlank()) {
            clearProtectionInRedis(null, normalizedIp);
            userProtectionRepository.findByIpOrigin(normalizedIp)
                .ifPresent(protection -> resetProtection(protection, now));
        }

        if (normalizedUsername != null && !normalizedUsername.isBlank()) {
            clearProtectionInRedis(normalizedUsername, null);
            userProtectionRepository.findByUser_Username(normalizedUsername)
                .ifPresent(protection -> resetProtection(protection, now));
        }

    }

    @Override
    public void unblockIp(String ip) {
        if (ip == null || ip.isBlank()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedIp = ip.trim();
        clearProtectionInRedis(null, normalizedIp);

        UserProtection protection = userProtectionRepository.findByIpOrigin(normalizedIp).orElse(null);
        if (protection == null) {
            return;
        }

        LocalDateTime now = LocalDateTime.now();

        resetProtection(protection, now);
        
    }

    @Override
    public void unblockUser(String username) {
        if (username == null || username.isBlank()) {
            throw new UserProtectionException(INVALID_INPUT_MESSAGE);
        }

        String normalizedUsername = username.trim();
        clearProtectionInRedis(normalizedUsername, null);

        UserProtection protection = userProtectionRepository.findByUser_Username(normalizedUsername).orElse(null);
        if (protection == null) {
            return;
        }

        LocalDateTime now = LocalDateTime.now();

        resetProtection(protection, now);
        
    }

    
    private void resetProtection(UserProtection protection, LocalDateTime now) {
        protection.setNumTrys(0);
        protection.setLastTry(now);
        protection.setBloquedAt(null);
        protection.setActive(false);
        userProtectionRepository.save(protection);
    }

    
    private void applyBlock(UserProtection protection, LocalDateTime blockedAt, boolean countAsAttempt) {
        if (countAsAttempt) {
            protection.setNumTrys(protection.getNumTrys() + 1);
        }
        protection.setLastTry(LocalDateTime.now());
        protection.setBloquedAt(blockedAt);
        protection.setActive(true);
        userProtectionRepository.save(protection);
    }

    private Optional<Instant> getBlockedUntil(Optional<UserProtection> protectionOptional) {
        if (protectionOptional.isEmpty()) {
            return Optional.empty();
        }

        LocalDateTime blockedAt = protectionOptional.get().getBloquedAt();
        if (blockedAt == null || !blockedAt.isAfter(LocalDateTime.now())) {
            return Optional.empty();
        }

        return Optional.of(blockedAt.atZone(ZoneId.systemDefault()).toInstant());
    }

    private UserProtection buildIpProtection(String ip, LocalDateTime now) {
        return UserProtection.builder()
            .ipOrigin(ip)
            .numTrys(0)
            .active(false)
            .lastTry(now)
            .build();
    }

    private UserProtection buildUserProtection(String username, String ip, LocalDateTime now) {
        return UserProtection.builder()
            .user(userService.findUser(username))
            .ipOrigin(ip)
            .numTrys(0)
            .active(false)
            .lastTry(now)
            .build();
    }

    private void registerFailedAttemptInRedis(String username, String ip) {
        try {
            registerFailedAttemptByKey(ipTriesKey(ip), ipBlockKey(ip));
            registerFailedAttemptByKey(userTriesKey(username), userBlockKey(username));
        } catch (RuntimeException ex) {
            log.warn("Redis unavailable while recording failed attempt for username={} ip={}. Falling back to DB only.", username, ip, ex);
        }
    }

    private void registerFailedAttemptByKey(String triesKey, String blockKey) {
        ValueOperations<String, String> operations = redisTemplate.opsForValue();
        Long attempts = operations.increment(triesKey);

        if (attempts != null && attempts == 1L) {
            redisTemplate.expire(triesKey, BLOCK_DURATION);
        }

        if (attempts != null && attempts >= MAX_FAILED_ATTEMPTS) {
            operations.set(blockKey, "1", BLOCK_DURATION);
        }
    }

    private void updateRedisBlock(String blockKey, String triesKey, Duration duration) {
        try {
            redisTemplate.opsForValue().set(blockKey, "1", duration);
            redisTemplate.delete(triesKey);
        } catch (RuntimeException ex) {
            log.warn("Redis unavailable while writing administrative block key={}", blockKey, ex);
        }
    }

    private boolean isBlockedInRedis(String blockKey) {
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(blockKey));
        } catch (RuntimeException ex) {
            log.warn("Redis unavailable while checking block key={}", blockKey, ex);
            return false;
        }
    }

    private Optional<Instant> getBlockedUntilFromRedis(String blockKey) {
        try {
            Long ttl = redisTemplate.getExpire(blockKey, TimeUnit.SECONDS);
            if (ttl == null || ttl <= 0) {
                return Optional.empty();
            }
            return Optional.of(Instant.now().plusSeconds(ttl));
        } catch (RuntimeException ex) {
            log.warn("Redis unavailable while checking block TTL for key={}", blockKey, ex);
            return Optional.empty();
        }
    }

    private Integer getAttemptsFromRedis(String triesKey) {
        try {
            String value = redisTemplate.opsForValue().get(triesKey);
            if (value == null || value.isBlank()) {
                return null;
            }
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            redisTemplate.delete(triesKey);
            return null;
        } catch (RuntimeException ex) {
            log.warn("Redis unavailable while checking attempts key={}", triesKey, ex);
            return null;
        }
    }

    private void clearProtectionInRedis(String username, String ip) {
        try {
            if (ip != null && !ip.isBlank()) {
                redisTemplate.delete(List.of(ipTriesKey(ip), ipBlockKey(ip)));
            }
            if (username != null && !username.isBlank()) {
                redisTemplate.delete(List.of(userTriesKey(username), userBlockKey(username)));
            }
        } catch (RuntimeException ex) {
            log.warn("Redis unavailable while clearing protection keys for username={} ip={}", username, ip, ex);
        }
    }

    private String ipTriesKey(String ip) {
        return IP_TRIES_KEY + ip;
    }

    private String userTriesKey(String username) {
        return USER_TRIES_KEY + username;
    }

    private String ipBlockKey(String ip) {
        return IP_BLOCK_KEY + ip;
    }

    private String userBlockKey(String username) {
        return USER_BLOCK_KEY + username;
    }

    @Override
    public List<ProtectionResponse> getAllUserProtections() {
        List<UserProtection> protections = userProtectionRepository.findAll();
        
        return protections.stream().map(protection -> {
            var user = protection.getUser();
            if (user == null) {
                throw new UserNotFoundException("User it can't be found in the protection request");
            }
            return ProtectionResponse.builder()
            .ip(protection.getIpOrigin())
            .numTrys(protection.getNumTrys())
            .lastTry((protection.getLastTry()) == null ? null : protection.getLastTry().toString())
            .bloquedAt((protection.getBloquedAt()) == null ? null : protection.getBloquedAt().toString())
            .active(protection.isActive())
            .username(user.getUsername())
            .email(user.getEmail())
            .enable(user.getEnabled())
            .createAt((user.getCreatedAt() == null) ? null : user.getCreatedAt().toString())
            .updatedAt((user.getUpdatedAt() == null) ? null :user.getUpdatedAt().toString())
            .lastLogin((user.getLastLogin() == null) ? null :user.getLastLogin().toString())
            .role(user.getRole())
            .build();
        }).toList();
    }

    @Override
    public ProtectionResponse getUserProtectionByUsername(ProtectionUsernameRequest protectionUsername) {
        UserProtection protection = userProtectionRepository.findByUser_Username(protectionUsername.getUsername())
        .orElseThrow(() -> new UserProtectionException(INVALID_INPUT_MESSAGE));
        User user = protection.getUser();
        if (user == null) {
            throw new UserNotFoundException("User it can't be found in the protection request");
        }
        return ProtectionResponse.builder()
            .ip(protection.getIpOrigin())
            .numTrys(protection.getNumTrys())
            .lastTry((protection.getLastTry()) == null ? null : protection.getLastTry().toString())
            .bloquedAt((protection.getBloquedAt()) == null ? null : protection.getBloquedAt().toString())
            .active(protection.isActive())
            .username(user.getUsername())
            .email(user.getEmail())
            .enable(user.getEnabled())
            .createAt((user.getCreatedAt() == null) ? null : user.getCreatedAt().toString())
            .updatedAt((user.getUpdatedAt() == null) ? null :user.getUpdatedAt().toString())
            .lastLogin((user.getLastLogin() == null) ? null :user.getLastLogin().toString())
            .role(user.getRole())
            .build();
    }

    @Override
    public ProtectionResponse getUserProtectionByIp(ProtectionIpRequest protectionIp) {
        UserProtection protection = userProtectionRepository.findByIpOrigin(protectionIp.getIp())
        .orElseThrow(() -> new UserProtectionException(INVALID_INPUT_MESSAGE));
        User user = protection.getUser();
        if (user == null) {
            throw new UserNotFoundException("User it can't be found in the protection request");
        }
        return ProtectionResponse.builder()
            .ip(protection.getIpOrigin())
            .numTrys(protection.getNumTrys())
            .lastTry((protection.getLastTry()) == null ? null : protection.getLastTry().toString())
            .bloquedAt((protection.getBloquedAt()) == null ? null : protection.getBloquedAt().toString())
            .active(protection.isActive())
            .username(user.getUsername())
            .email(user.getEmail())
            .enable(user.getEnabled())
            .createAt((user.getCreatedAt() == null) ? null : user.getCreatedAt().toString())
            .updatedAt((user.getUpdatedAt() == null) ? null :user.getUpdatedAt().toString())
            .lastLogin((user.getLastLogin() == null) ? null :user.getLastLogin().toString())
            .role(user.getRole())
            .build();
    }

}
