package com.ivansario.secureauth.service.interfaces;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Servicio responsable de la protección frente a intentos de acceso abusivos
 * (fuerza bruta / credential stuffing). La implementación puede basarse en
 * una tabla en BD, en Redis o en memoria según escalabilidad requerida.
 */
public interface UserProtectionService {

	/**
	 * Comprueba si el usuario está bloqueado actualmente.
	 * @param username nombre de usuario (puede ser email o username)
	 * @return true si hay un bloqueo activo sobre el usuario
	 */
	boolean isUserBlocked(String username);

	/**
	 * Comprueba si la IP está bloqueada actualmente.
	 * @param ip Dirección IP (texto)
	 * @return true si la IP tiene un bloqueo activo
	 */
	boolean isIpBlocked(String ip);

	/**
	 * Combinación de comprobación por usuario e IP.
	 * @param username nombre de usuario
	 * @param ip dirección IP
	 * @return true si alguno de los criterios indica bloqueo
	 */
	boolean isBlocked(String username, String ip);

	/**
	 * Registra un intento fallido de autenticación para la pareja
	 * (usuario, ip). La implementación decide si incrementa contadores,
	 * aplica backoff o establece un bloqueo temporal.
	 * @param username nombre de usuario intentado (puede ser null/empty)
	 * @param ip dirección IP del origen
	 */
	void registerFailedAttempt(String username, String ip);

	/**
	 * Registra un inicio de sesión exitoso. Debe limpiar contadores y
	 * desbloquear recursos asociados al usuario/ip si procede.
	 * @param username nombre de usuario autenticado
	 * @param ip dirección IP del origen
	 */
	void registerSuccessfulLogin(String username, String ip);

	/**
	 * Obtiene el número aproximado de intentos fallidos acumulados para
	 * el usuario en el periodo configurado.
	 */
	int getFailedAttemptsForUser(String username);

	/**
	 * Obtiene el número aproximado de intentos fallidos acumulados para
	 * la IP en el periodo configurado.
	 */
	int getFailedAttemptsForIp(String ip);

	/**
	 * Resetea los contadores de fallos para la pareja (usuario, ip).
	 */
	void resetFailedAttempts(String username, String ip);

	/**
	 * Devuelve, si existe, el instante hasta el que el usuario está bloqueado.
	 */
	Optional<Instant> getBlockedUntilForUser(String username);

	/**
	 * Devuelve, si existe, el instante hasta el que la IP está bloqueada.
	 */
	Optional<Instant> getBlockedUntilForIp(String ip);

	/**
	 * Bloqueo administrativo temporal sobre un usuario.
	 */
	void blockUser(String username, Duration duration);

	/**
	 * Levanta un bloqueo administrativo sobre un usuario.
	 */
	void unblockUser(String username);

	/**
	 * Bloqueo administrativo temporal sobre una IP.
	 */
	void blockIp(String ip, Duration duration);

	/**
	 * Levanta un bloqueo administrativo sobre una IP.
	 */
	void unblockIp(String ip);

}
