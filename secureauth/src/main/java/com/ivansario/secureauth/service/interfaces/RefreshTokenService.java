package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;

/**
 * Service contract for refresh token lifecycle operations.
 */
public interface RefreshTokenService {

    /**
     * Returns all refresh tokens.
     *
     * @return list of refresh tokens
     */
    List<RefreshToken> findAll();

    /**
     * Finds a refresh token by identifier.
     *
     * @param id refresh token id
     * @return matching refresh token
     */
    RefreshToken findById(UUID id);

    /**
     * Finds the refresh token associated with a user.
     *
     * @param user target user
     * @return matching refresh token or {@code null}
     */
    RefreshToken findByUser(User user);

    /**
     * Finds a refresh token by token value.
     *
     * @param token token value
     * @return matching refresh token or {@code null}
     */
    RefreshToken findByToken(String token);

    /**
     * Creates a refresh token for a user.
     *
     * @param user token owner
     * @param ipAddress source IP address
     * @param userAgent client user-agent
     * @return created refresh token
     */
    RefreshToken create(User user, String ipAddress, String userAgent);

    /**
     * Revokes the provided refresh token.
     *
     * @param foundRefreshToken token to revoke
     * @return updated refresh token
     */
    RefreshToken revokeToken(RefreshToken foundRefreshToken);

    /**
     * Revokes all refresh tokens linked to a user.
     *
     * @param user token owner
     */
    void revokeAllTokensByUser(User user);

    /**
     * Deletes a refresh token by identifier.
     *
     * @param id refresh token id
     * @return {@code true} when deletion succeeded
     */
    boolean delete(UUID id);

    /**
     * Rotates an existing refresh token and updates metadata.
     *
     * @param existingRefreshToken token to rotate
     * @param ipAddress source IP address
     * @param userAgent client user-agent
     * @return updated refresh token
     */
    RefreshToken updateToken(RefreshToken existingRefreshToken, String ipAddress, String userAgent);

    /**
     * Indicates whether a user currently has a refresh token.
     *
     * @param user user to check
     * @return {@code true} when at least one refresh token exists
     */
    boolean existsRefreshTokenByUser(User user);

    /**
     * Deletes refresh token data for a user.
     *
     * @param user token owner
     * @return {@code true} when a token was found and deleted
     */
    boolean deleteByUser(User user);

}
