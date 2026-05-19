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
import com.ivansario.secureauth.exception.UserExistsException;
import com.ivansario.secureauth.exception.UserNotFoundException;
import com.ivansario.secureauth.security.JwtUtil;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.RoleService;
import com.ivansario.secureauth.service.interfaces.UserRoleService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;
import com.ivansario.secureauth.util.RoleEnum;

import io.swagger.v3.oas.annotations.parameters.RequestBody;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;

/**
 * Implementación del servicio de autenticación.
*
* Proporciona operaciones de login, logout, refresh token y registro de
* usuarios.
*/
@Service
@Slf4j
@Validated
@RequiredArgsConstructor
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
    public AuthResponse login(@Valid @RequestBody LoginRequest request, String ipAddress, String userAgent) {

        Authentication authentication = authenticate(request.getUsername(), request.getPassword());

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userService.findUser(userDetails.getUsername());

        if (user == null) {
            throw new UserNotFoundException("Usuario no encontrado: " + userDetails.getUsername());
        }

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(userDetails);
        } catch (Exception e) {
            throw new TokenGenerationException("No se pudo generar access token", e);
        }

        RefreshToken refreshedToken = createOrUpdateRefreshTokenAndSession(user, ipAddress, userAgent);

        user.setLastLogin(LocalDateTime.now());
        User userNewLastLogin = userService.updateUser(user);
        validateCreatedEntity(userNewLastLogin, "User");

        log.info("Usuario {} inició sesión exitosamente. IP: {}", userNewLastLogin.getUsername(), ipAddress);

        return AuthResponse.builder()
                .username(userNewLastLogin.getUsername())
                .email(userNewLastLogin.getEmail())
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
    public void logout(@Valid @RequestBody RefreshTokenRequest logoutRefreshToken) {
        
        RefreshToken foundRefreshToken = refreshTokenService.findByToken(logoutRefreshToken.getToken());
        validateRefreshToken(foundRefreshToken);

        User user = foundRefreshToken.getUser();

        // Revocar refresh token
        refreshTokenService.revokeToken(foundRefreshToken);

        // Revocar sesión del usuario
        userSessionService.revokeSession(user);

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
    public AuthResponse refreshToken(@Valid @RequestBody RefreshTokenRequest request, String ipAddress, String userAgent) {
        RefreshToken oldToken = refreshTokenService.findByToken(request.getToken());
        validateRefreshToken(oldToken);
        if (oldToken.isRevoked()) {
            throw new SessionCreationException("El token del usuario ha sido revocada");
        }

        User user = oldToken.getUser();

        UserSession userSession = userSessionService.findByUser(user);
        if (userSession == null || userSession.isRevoked()) {
            throw new SessionCreationException("La sesión del usuario fue revocada");
        }
        UserDetails userDetails = resolveUserDetails(user);

        RefreshToken newToken = createOrUpdateRefreshTokenAndSession(user, ipAddress, userAgent);

        userSession.setRefreshToken(newToken);
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
                .refreshToken(newToken.getToken())
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
            @Valid @RequestBody
            CreateUserRequest request,
            String ipAddress,
            String userAgent,
            RoleEnum roleType) {

        if (userService.existsUser(request.getEmail())) {
            throw new UserExistsException("Email ya registrado");
        }

        Role role = roleService.findByName(roleType);
        if (role == null) {
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
    public AuthResponse changePassword(
            @Valid @RequestBody 
            NewPasswordUserRequest request, 
            String ipAddress, 
            String userAgent) {

        String pass1 = request.getNewPassword();
        String pass2 = request.getConfirmPassword();

        if (!pass1.equals(pass2)) { 
            throw new InvalidConfirmationPasswordException("Las contraseñas proporcionadas no son válidas");
        }

        String token = request.getToken();

        RefreshToken refreshToken = refreshTokenService.findByToken(token);
        if (refreshToken == null || refreshToken.isExpired()) {
            throw new RefreshTokenExpiredException("Refresh token expirado");
        }

        if (userService.existsUser(refreshToken.getUser().getEmail())) {
            throw new UserNotFoundException("Email ya registrado");
        }

        User userNewPassword = userService.changePassword(refreshToken.getUser(), pass1);
        validateCreatedEntity(userNewPassword, "User");

        Authentication authentication = authenticate(userNewPassword.getUsername(), userNewPassword.getPassword());

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String accessToken;
        try {
            accessToken = jwtUtil.generateToken(userDetails);
        } catch (Exception e) {
            throw new TokenGenerationException("No se pudo generar access token", e);
        }

        RefreshToken refreshedToken = createOrUpdateRefreshTokenAndSession(userNewPassword, ipAddress, userAgent);

        log.info("ChangePassword {} exitosamente. Debe hacer login para obtener acceso.", userNewPassword.getUsername());


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
            throw new RuntimeException("Error: " + entityName + " no creado");
        }
    }

    /**
     * Valida la existencia y estado del refresh token.
     */
    private void validateRefreshToken(RefreshToken refreshToken) {
        if (refreshToken == null) {
            throw new InvalidRefreshTokenException("Refresh token no válido");
        }
        if (refreshToken.isExpired()) {
            throw new RefreshTokenExpiredException("Refresh token expirado");
        }
        if (!refreshToken.getUser().getEnabled()) {
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
        validateRefreshToken(refreshedToken);

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
