package com.ivansario.secureauth.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.dto.RegisterResponse;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.util.RoleEnum;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


/**
 * Controlador REST para operaciones de autenticación.
 * <p>
 * Expone endpoints para login, registro, cierre de sesión y renovación de tokens.
 * </p>
*/
@RestController
@Tag(name = "SecureAuth_api", description = "Operaciones CRUD de authenticación y gestión de usuarios")
@RequiredArgsConstructor
@RequestMapping(path = "/api/auth/")
public class AuthController {

    private final AuthService authService;

    /**
     * Endpoint POST /login - autentica al usuario y devuelve tokens.
     *
     * @param loginRequest solicitud con credenciales (username, password)
     * @param request HTTP servlet request (se usa para IP y User-Agent)
     * @return ResponseEntity con {@link AuthResponse} que contiene access y refresh token
     */
    @PostMapping("/login")
    @Operation(
        summary = "Iniciar sesión",
        description = "Autentica un usuario y devuelve access token, refresh token y datos básicos del perfil."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Autenticación exitosa"),
        @ApiResponse(responseCode = "400", description = "Datos de login inválidos"),
        @ApiResponse(responseCode = "401", description = "Credenciales incorrectas")
    })
    public ResponseEntity<AuthResponse> login(
        @Valid @RequestBody 
        LoginRequest loginRequest, 
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(authService.login(loginRequest, ipAddress, userAgent));
    }

    /**
     * Endpoint POST /register - registra un nuevo usuario con rol USER.
     *
     * @param requestCreateUser datos para crear el usuario
     * @param request HTTP servlet request (se usa para IP y User-Agent)
     * @return ResponseEntity con {@link RegisterResponse} con información del nuevo usuario
     */
    @PostMapping("/register")
    @Operation(
        summary = "Registrar usuario",
        description = "Crea un nuevo usuario con el rol ROLE_USER y devuelve los datos registrados."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Usuario registrado correctamente"),
        @ApiResponse(responseCode = "400", description = "Datos de registro inválidos"),
        @ApiResponse(responseCode = "409", description = "El usuario ya existe")
    })
    public ResponseEntity<RegisterResponse> registerUser(
        @Valid @RequestBody 
        CreateUserRequest requestCreateUser,
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(authService.register(requestCreateUser, 
                ipAddress, 
                userAgent, 
                RoleEnum.ROLE_USER
            )
        );
    }
    
    /**
     * Endpoint POST /logout - invalida un refresh token y revoca la sesión.
     *
     * @param request petición que contiene el refresh token a revocar
     * @return ResponseEntity vacío con código 204 cuando se revoca correctamente
     */
    @PostMapping("/logout")
    @Operation(
        summary = "Cerrar sesión",
        description = "Revoca el refresh token proporcionado y marca la sesión del usuario como revocada."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Sesión cerrada correctamente"),
        @ApiResponse(responseCode = "400", description = "Refresh token inválido"),
        @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request);
        return ResponseEntity.noContent().build();
    }

    /**
     * Endpoint POST /refresh - renueva access y refresh tokens dado un refresh token válido.
     *
     * @param refreshTokenRequest petición con el refresh token actual
     * @param request HTTP servlet request (se usa para IP y User-Agent)
     * @return ResponseEntity con {@link AuthResponse} que contiene los nuevos tokens
     */
    @PostMapping("/refresh")
    @Operation(
        summary = "Renovar tokens",
        description = "Intercambia un refresh token válido por un nuevo access token y refresh token."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Tokens renovados correctamente"),
        @ApiResponse(responseCode = "400", description = "Refresh token inválido o expirado"),
        @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<AuthResponse> refreshToken(
        @Valid @RequestBody 
        RefreshTokenRequest refreshTokenRequest, 
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest, ipAddress, userAgent));
    }

    @PostMapping("/newPassword")
    @Operation(
        summary = "Cambiar contraseña",
        description = "Actualiza la contraseña del usuario autenticado y devuelve tokens renovados."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Contraseña actualizada correctamente"),
        @ApiResponse(responseCode = "400", description = "Datos de cambio de contraseña inválidos"),
        @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<AuthResponse> changePassword(
        @Valid @RequestBody
        NewPasswordUserRequest newPasswordUser,
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(authService.changePassword(newPasswordUser, ipAddress, userAgent));
    }

}
