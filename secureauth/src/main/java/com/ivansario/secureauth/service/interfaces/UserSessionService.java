package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;

/**
 * Service contract for user session lifecycle operations.
 */
public interface UserSessionService {

    /**
     * Returns all user sessions.
     *
     * @return list of sessions
     */
    List<UserSession> findAll();

    /**
     * Finds a session by identifier.
     *
     * @param id session id
     * @return matching session
     */
    UserSession findById(UUID id);

    /**
     * Finds the current session for a user.
     *
     * @param user target user
     * @return matching session or {@code null}
     */
    UserSession findByUser(User user);

    /**
     * Creates a new user session.
     *
     * @param user session owner
     * @param refreshToken associated refresh token
     * @param ipAddress source IP address
     * @param UserAgent client user-agent
     * @return created session
     */
    UserSession create(User user, RefreshToken refreshToken, String ipAddress, String UserAgent);

    /**
     * Updates a user session.
     *
     * @param session session to update
     * @return updated session
     */
    UserSession update(UserSession session);

    /**
     * Revokes the active user session when present.
     *
     * @param user target user
     * @return {@code true} when a session was revoked
     */
    boolean revokeSession(User user);

    /**
     * Deletes the session associated with a user.
     *
     * @param user target user
     * @return {@code true} when a session was found and removed
     */
    boolean deleteByUser(User user);

}
