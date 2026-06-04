package com.ivansario.secureauth.exception;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler extends Exception {

	@ExceptionHandler(UserNotFoundException.class)
	public ResponseEntity<Map<String, Object>> handleUserNotFound(UserNotFoundException ex) {
		log.error("User not found: {}", ex.getMessage());
		return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage());
	}

	@ExceptionHandler(EntityNotFoundException.class)
	public ResponseEntity<Map<String, Object>> handleEntityNotFound(EntityNotFoundException ex) {
		log.error("Entity not found: {}", ex.getMessage());
		return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage());
	}

	@ExceptionHandler(InvalidCredentialsException.class)
	public ResponseEntity<Map<String, Object>> handleInvalidCredentials(InvalidCredentialsException ex) {
		log.warn("Invalid credentials: {}", ex.getMessage());
		return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
	}

	@ExceptionHandler(InvalidPasswordProvided.class)
	public ResponseEntity<Map<String, Object>> handleInvalidPassword(InvalidPasswordProvided ex) {
		log.warn("Password is too common or obvious");
		return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
	}

	@ExceptionHandler(TokenGenerationException.class)
	public ResponseEntity<Map<String, Object>> handleTokenGeneration(TokenGenerationException ex) {
		log.error("Error generating token: {}", ex.getMessage(), ex);
		return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
	}

	@ExceptionHandler(SessionCreationException.class)
	public ResponseEntity<Map<String, Object>> handleSessionCreation(SessionCreationException ex) {
		log.error("Error creating session: {}", ex.getMessage());
		return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
	}

	@ExceptionHandler(SessionRevokeException.class)
	public ResponseEntity<Map<String, Object>> handleSessionRevoke(SessionRevokeException ex) {
		log.error("Error revoking session: {}", ex.getMessage());
		return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
	}

	@ExceptionHandler(UserCreationException.class)
	public ResponseEntity<Map<String, Object>> handleUserCreation(UserCreationException ex) {
		log.error("Error creating user: {}", ex.getMessage(), ex);
		return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
	}

	@ExceptionHandler(InvalidRefreshTokenException.class)
	public ResponseEntity<Map<String, Object>> handleInvalidRefreshToken(InvalidRefreshTokenException ex) {
		log.warn("Invalid refresh token: {}", ex.getMessage());
		return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
	}

	@ExceptionHandler(RefreshTokenExpiredException.class)
	public ResponseEntity<Map<String, Object>> handleRefreshTokenExpired(RefreshTokenExpiredException ex) {
		log.warn("Refresh token expired: {}", ex.getMessage());
		return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
	}

	@ExceptionHandler(RefreshTokenRevokedException.class)
	public ResponseEntity<Map<String, Object>> handleRefreshTokenRevoked(RefreshTokenRevokedException ex) {
		log.warn("Refresh token revoked: {}", ex.getMessage());
		return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
	}

	@ExceptionHandler(RefreshTokenRotationException.class)
	public ResponseEntity<Map<String, Object>> handleRefreshTokenRotation(RefreshTokenRotationException ex) {
		log.error("Error rotating refresh token: {}", ex.getMessage());
		return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
	}

	@ExceptionHandler(InvalidConfirmationPasswordException.class)
	public ResponseEntity<Map<String, Object>> handleInvalidConfirmationPassword(InvalidConfirmationPasswordException ex) {
		log.warn("Invalid password confirmation: {}", ex.getMessage());
		return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
	}

	@ExceptionHandler(UserExistsException.class)
	public ResponseEntity<Map<String, Object>> handleUserExists(UserExistsException ex) {
		log.warn("User already exists: {}", ex.getMessage());
		return buildResponse(HttpStatus.CONFLICT, ex.getMessage());
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
		log.warn("Invalid argument: {}", ex.getMessage());
		return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
		Map<String, Object> body = new LinkedHashMap<>();
		Map<String, String> errors = new LinkedHashMap<>();

		for (FieldError error : ex.getBindingResult().getFieldErrors()) {
			errors.put(error.getField(), error.getDefaultMessage());
		}

		body.put("timestamp", LocalDateTime.now());
		body.put("status", HttpStatus.BAD_REQUEST.value());
		body.put("error", HttpStatus.BAD_REQUEST.getReasonPhrase());
		body.put("message", "Validation failed");
		body.put("errors", errors);

		log.warn("Validation error: {}", errors);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex) {
		log.warn("Access denied: {}", ex.getMessage());
		return buildResponse(HttpStatus.FORBIDDEN, ex.getMessage());
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex) {
		log.error("Unexpected error: {}", ex.getMessage(), ex);
		return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected error occurred");
	}

	private ResponseEntity<Map<String, Object>> buildResponse(HttpStatus status, String message) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("timestamp", LocalDateTime.now());
		body.put("status", status.value());
		body.put("error", status.getReasonPhrase());
		body.put("message", message != null && !message.isBlank() ? message : status.getReasonPhrase());
		return ResponseEntity.status(status).body(body);
	}
}
