package com.ivansario.secureauth.service;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.dto.RegisterResponse;
import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.Role;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserRole;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.exception.InvalidConfirmationPasswordException;
import com.ivansario.secureauth.exception.InvalidCredentialsException;
import com.ivansario.secureauth.exception.InvalidRefreshTokenException;
import com.ivansario.secureauth.exception.RefreshTokenExpiredException;
import com.ivansario.secureauth.exception.SessionCreationException;
import com.ivansario.secureauth.exception.TokenGenerationException;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.security.JwtUtil;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.RoleService;
import com.ivansario.secureauth.service.interfaces.UserRoleService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;
import com.ivansario.secureauth.util.RoleEnum;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
/**
 * Implementación del servicio de autenticación.
 *
 * Proporciona operaciones de login, logout, refresh token y registro de
 * usuarios.
 */
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    private final UserServiceImpl userService;
    private final RefreshTokenService refreshTokenService;
    private final UserSessionService userSessionService;
    private final RoleService roleService;
    private final UserRoleService userRoleService;

    /**
     * Autentica al usuario y genera access y refresh tokens, además de
     * crear/actualizar
     * la sesión del usuario.
     *
     * @param request   datos de login (username, password)
     * @param ipAddress dirección IP del cliente
     * @param userAgent información del cliente (User-Agent)
     * @return {@link AuthResponse} con tokens y datos del usuario
     */
    @Override
    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {

        Authentication authentication = authenticate(request.getUsername(), request.getPassword());

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userService.findUser(userDetails.getUsername());

        if (user == null) {
            log.error("Usuario no encontrado después de autenticación: {}", userDetails.getUsername());
            throw new UserNotFoundException("Usuario no encontrado: " + userDetails.getUsername());
        }

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(userDetails);
        } catch (Exception e) {
            log.error("Error generando access token para usuario: {}", user.getUsername(), e);
            throw new TokenGenerationException("No se pudo generar access token", e);
        }

        RefreshToken refreshedToken = createOrUpdateRefreshTokenAndSession(user, ipAddress, userAgent);

        user.setLastLogin(LocalDateTime.now());
        userService.updateUser(user);

        log.info("Usuario {} inició sesión exitosamente. IP: {}", user.getUsername(), ipAddress);

        return AuthResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .role(toRoleNames(user))
                .accessToken(accessToken)
                .refreshToken(refreshedToken.getToken())
                .build();
    }

    /**
     * Cierra la sesión asociada al refresh token proporcionado y revoca el token.
     *
     * @param logoutRefreshToken petición que contiene el refresh token a revocar
     */
    @Override
    @Transactional
    public void logout(RefreshTokenRequest logoutRefreshToken) {
        RefreshToken foundRefreshToken = refreshTokenService.findByToken(logoutRefreshToken.getToken());
        validateRefreshToken(foundRefreshToken);

        User user = foundRefreshToken.getUser();

        // Revocar refresh token
        refreshTokenService.revokeToken(foundRefreshToken);

        // Revocar sesión del usuario
        userSessionService.revokeLastSession(user);

        log.info("Usuario {} se ha desconectado exitosamente", user.getUsername());
    }

    /**
     * Renueva los tokens (access y refresh) utilizando un refresh token válido.
     *
     * @param refreshTokenRequest petición que contiene el refresh token actual
     * @param ipAddress           dirección IP del cliente
     * @param userAgent           información del cliente (User-Agent)
     * @return {@link AuthResponse} con los nuevos tokens
     */
    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest, String ipAddress, String userAgent) {
        RefreshToken oldRefreshToken = refreshTokenService.findByToken(refreshTokenRequest.getToken());
        validateRefreshToken(oldRefreshToken);
        if (oldRefreshToken.isRevoked()) {
            log.error("Token del usuario ha sido revocada: {}", oldRefreshToken.getUser().getUsername());
            throw new SessionCreationException("El token del usuario ha sido revocada");
        }

        User user = oldRefreshToken.getUser();

        UserSession userSession = userSessionService.findByUser(user);
        if (userSession == null || userSession.isRevoked()) {
            log.error("La sesión del usuario fue revocada: {}", user.getUsername());
            throw new SessionCreationException("La sesión del usuario fue revocada");
        }
        UserDetails userDetails = resolveUserDetails(user);

        RefreshToken refreshedToken = refreshTokenService.updateToken(oldRefreshToken, ipAddress, userAgent);
        validateCreatedEntity(refreshedToken, "Revoked old refresh token");

        userSession.setRefreshToken(refreshedToken);
        userSession.setIpAddress(ipAddress);
        userSession.setDeviceInfo(userAgent);
        userSessionService.update(userSession);

        String newAccessToken = jwtUtil.generateToken(userDetails);

        log.info("RefreshToken ejecutado para usuario: {}. IP: {}", user.getUsername(), ipAddress);

        return AuthResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .role(toRoleNames(user))
                .accessToken(newAccessToken)
                .refreshToken(refreshedToken.getToken())
                .build();
    }

    /**
     * Registra un nuevo usuario con el rol especificado.
     *
     * @param request   datos para crear el usuario
     * @param ipAddress dirección IP del cliente
     * @param userAgent información del cliente (User-Agent)
     * @param roleType  rol a asignar al usuario
     * @return {@link RegisterResponse} con información del usuario creado
     */
    @Override
    @Transactional
    public RegisterResponse register(
            CreateUserRequest request,
            String ipAddress,
            String userAgent,
            RoleEnum roleType) {

        if (userService.existsUser(request.getEmail())) {
            throw new RuntimeException("Email ya registrado");
        }

        Role role = roleService.findByName(roleType);
        if (role == null) {
            log.error("Error: Rol no encontrado: " + roleType);
            throw new RuntimeException("Error: Rol no encontrado: " + roleType);
        }

        User user = userService.createUser(request, role);
        validateCreatedEntity(user, "Usuario");

        UserRole userRole = userRoleService.create(user, role);
        validateCreatedEntity(userRole, "Rol de usuario");

        user.setUserRoles(Set.of(userRole));

        log.info("Usuario {} registrado exitosamente. Debe hacer login para obtener acceso.", user.getUsername());

        return RegisterResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .role(toRoleNames(user))
                .build();
    }

    @Override
    @Transactional
    public AuthResponse changePassword(NewPasswordUserRequest request, String ipAddress, String userAgent) {

        String pass1 = request.getNewPassword();
        String pass2 = request.getConfirmPassword();

        if (!pass1.equals(pass2)) { 
            log.error("Las contraseñas proporcionadas no son válidas");
            throw new InvalidConfirmationPasswordException("Las contraseñas proporcionadas no son válidas");
        }

        String token = request.getToken();

        RefreshToken refreshToken = refreshTokenService.findByToken(token);
        if (refreshToken == null || refreshToken.isExpired()) {
            log.error("Refresh token expirado");
            throw new RefreshTokenExpiredException("Refresh token expirado");
        }

        User userNewPassword = userService.changePassword(refreshToken.getUser(), pass1);

        Authentication authentication = authenticate(userNewPassword.getUsername(), userNewPassword.getPassword());

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(userDetails);
        } catch (Exception e) {
            log.error("Error generando access token para usuario: {}", userNewPassword.getUsername(), e);
            throw new TokenGenerationException("No se pudo generar access token", e);
        }

        RefreshToken refreshedToken = createOrUpdateRefreshTokenAndSession(userNewPassword, ipAddress, userAgent);

        return AuthResponse.builder()
                .username(userNewPassword.getUsername())
                .email(userNewPassword.getEmail())
                .role(toRoleNames(userNewPassword))
                .accessToken(accessToken)
                .refreshToken(refreshedToken.getToken())
                .build();
    }

    /**
     * Realiza la autenticación usando el {@code AuthenticationManager}.
     */
    private Authentication authenticate(String username, String password) {
        try {
            return authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
        } catch (AuthenticationException e) {
            try {
                User user = userService.findUser(username);
                return authManager.authenticate(
                        new UsernamePasswordAuthenticationToken(user.getEmail(), password));
            } catch (Exception fallbackException) {
                log.warn("Intento de login fallido para usuario: {}", username);
                throw new InvalidCredentialsException("Credenciales inválidas");
            }
        }
    }

    /**
     * Valida que una entidad creada no sea nula; lanza RuntimeException en caso
     * contrario.
     */
    private void validateCreatedEntity(Object entity, String entityName) {
        if (entity == null) {
            log.error("Error: {} no creado", entityName);
            throw new RuntimeException("Error: " + entityName + " no creado");
        }
    }

    /**
     * Valida la existencia y estado del refresh token.
     */
    private void validateRefreshToken(RefreshToken refreshToken) {
        if (refreshToken == null) {
            log.error("Refresh token no válido");
            throw new InvalidRefreshTokenException("Refresh token no válido");
        }
        if (refreshToken.isExpired()) {
            log.error("Refresh token expirado");
            throw new RefreshTokenExpiredException("Refresh token expirado");
        }
        if (!refreshToken.getUser().getEnabled()) {
            log.error("Refresh token no válido");
            throw new UserNotFoundException("Usuario inactivo");
        }
    }

    /**
     * Crea o actualiza el refresh token y sincroniza la sesión del usuario.
     */
    private RefreshToken createOrUpdateRefreshTokenAndSession(User user, String ipAddress, String userAgent) {
        RefreshToken refreshedToken;
        if (refreshTokenService.existsRefreshTokenByUser(user)) {
            refreshedToken = refreshTokenService.updateToken(refreshTokenService.findByUser(user), ipAddress, userAgent);
        } else {
            refreshedToken = refreshTokenService.create(user, ipAddress, userAgent);
        }

        upsertUserSession(user, refreshedToken, ipAddress, userAgent);
        return refreshedToken;
    }

    /**
     * Crea o actualiza la sesión de usuario con el token y metadatos actuales.
     */
    private void upsertUserSession(User user, RefreshToken refreshToken, String ipAddress, String userAgent) {
        UserSession userSession = userSessionService.findByUser(user);
        if (userSession == null) {
            userSessionService.create(user, refreshToken, ipAddress, userAgent);
        } else {
            userSession.setRefreshToken(refreshToken);
            userSession.setIpAddress(ipAddress);
            userSession.setDeviceInfo(userAgent);
            userSession.setRevoked(false);
            userSessionService.update(userSession);
        }
    }

    /**
     * Resuelve los detalles de usuario necesarios para generar tokens.
     */
    private UserDetails resolveUserDetails(User user) {
        try {
            return (UserDetails) userService.loadUserByUsername(user.getEmail());
        } catch (Exception emailException) {
            log.warn("No se pudo cargar el usuario por email {}, intentando por username {}", user.getEmail(),
                    user.getUsername());

            try {
                return (UserDetails) userService.findUser(user.getUsername());
            } catch (Exception usernameException) {
                log.error("Usuario no encontrado por email ni username: email={}, username={}", user.getEmail(),
                        user.getUsername());
                throw new UserNotFoundException("Usuario no encontrado: " + user.getUsername());
            }
        }
    }

    /**
     * Convierte el conjunto de roles de la entidad {@code User} a nombres de rol.
     */
    private Set<String> toRoleNames(User user) {
        return user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());
    }
}
