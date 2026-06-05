package com.ivansario.secureauth.service.interfaces;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.ivansario.secureauth.dto.protect.ProtectionIpRequest;
import com.ivansario.secureauth.dto.protect.ProtectionResponse;
import com.ivansario.secureauth.dto.protect.ProtectionUsernameRequest;

/**
 * Service responsible for protecting against abusive access attempts
 * (brute force / credential stuffing). The implementation may rely on
 * a database table, Redis, or in-memory storage depending on scalability needs.
 */
public interface UserProtectionService {

	/**
	 * Checks whether the user is currently blocked.
	 *
	 * @param username user identifier, which may be an email address or username
	 * @return {@code true} when the user has an active block
	 */
	boolean isUserBlocked(String username);

	/**
	 * Checks whether the IP address is currently blocked.
	 *
	 * @param ip IP address in text form
	 * @return {@code true} when the IP address has an active block
	 */
	boolean isIpBlocked(String ip);

	/**
	 * Checks whether access should be blocked based on either the user or IP address.
	 *
	 * @param username user identifier
	 * @param ip IP address
	 * @return {@code true} when either criterion indicates an active block
	 */
	boolean isBlocked(String username, String ip);

	/**
	 * Records a failed authentication attempt for the given user and IP pair.
	 * The implementation decides whether to increase counters, apply backoff,
	 * or create a temporary block.
	 *
	 * @param username attempted user identifier, which may be {@code null} or empty
	 * @param ip source IP address
	 */
	void registerFailedAttempt(String username, String ip);

	/**
	 * Records a successful login. Implementations should clear counters and
	 * remove any associated user or IP blocks when appropriate.
	 *
	 * @param username authenticated user identifier
	 * @param ip source IP address
	 */
	void registerSuccessfulLogin(String username, String ip);

	/**
	 * Returns the approximate number of failed attempts accumulated for the user
	 * during the configured time window.
	 *
	 * @param username user identifier
	 * @return approximate number of failed attempts for the user
	 */
	int getFailedAttemptsForUser(String username);

	/**
	 * Returns the approximate number of failed attempts accumulated for the IP
	 * address during the configured time window.
	 *
	 * @param ip IP address
	 * @return approximate number of failed attempts for the IP address
	 */
	int getFailedAttemptsForIp(String ip);

	/**
	 * Resets failed-attempt counters for the given user and IP pair.
	 *
	 * @param username user identifier
	 * @param ip IP address
	 */
	void resetFailedAttempts(String username, String ip);

	/**
	 * Returns the instant until which the user remains blocked, if any.
	 *
	 * @param username user identifier
	 * @return the block expiration instant for the user, if present
	 */
	Optional<Instant> getBlockedUntilForUser(String username);

	/**
	 * Returns the instant until which the IP address remains blocked, if any.
	 *
	 * @param ip IP address
	 * @return the block expiration instant for the IP address, if present
	 */
	Optional<Instant> getBlockedUntilForIp(String ip);

	/**
	 * Applies a temporary administrative block to a user.
	 *
	 * @param username user identifier
	 * @param duration block duration
	 */
	void blockUser(String username, Duration duration);

	/**
	 * Removes an administrative block from a user.
	 *
	 * @param username user identifier
	 */
	void unblockUser(String username);

	/**
	 * Applies a temporary administrative block to an IP address.
	 *
	 * @param ip IP address
	 * @param duration block duration
	 */
	void blockIp(String ip, Duration duration);

	/**
	 * Removes an administrative block from an IP address.
	 *
	 * @param ip IP address
	 */
	void unblockIp(String ip);

	/**
	 * Returns the current protection entries tracked for users.
	 *
	 * @return list of user protection details
	 */
	List<ProtectionResponse> getAllUserProtections();

	/**
	 * Returns protection details for a specific user identifier.
	 *
	 * @param protectionUsername request payload containing the username to query
	 * @return protection details associated with the requested username
	 */
	ProtectionResponse getUserProtectionByUsername(ProtectionUsernameRequest protectionUsername);

	/**
	 * Returns protection details for a specific IP address.
	 *
	 * @param protectionIp request payload containing the IP address to query
	 * @return protection details associated with the requested IP address
	 */
	ProtectionResponse getUserProtectionByIp(ProtectionIpRequest protectionIp);

	/**
	 * Applies an administrative block to a user identified by username and returns
	 * the updated protection details.
	 *
	 * @param protectionUsername request payload containing the username to block
	 * @return updated protection details for the blocked user
	 */
	ProtectionResponse blockByUsername(ProtectionUsernameRequest protectionUsername);
	
	/**
	 * Applies an administrative block to an IP address and returns the updated
	 * protection details.
	 *
	 * @param protectionIp request payload containing the IP address to block
	 * @return updated protection details for the blocked IP address
	 */
	ProtectionResponse blockByIp(ProtectionIpRequest protectionIp);

	/**
	 * Removes an administrative block from a user identified by username and
	 * returns updated protection details.
	 *
	 * @param protectionUsername request payload containing the username to unblock
	 * @return updated protection details for the unblocked user
	 */
	ProtectionResponse unblockByUsername(ProtectionUsernameRequest protectionUsername);
	
	/**
	 * Removes an administrative block from an IP address and returns updated
	 * protection details.
	 *
	 * @param protectionIp request payload containing the IP address to unblock
	 * @return updated protection details for the unblocked IP address
	 */
	ProtectionResponse unblockByIp(ProtectionIpRequest protectionIp);

}
