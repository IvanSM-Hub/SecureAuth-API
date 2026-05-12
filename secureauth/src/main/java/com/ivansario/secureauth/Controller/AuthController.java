package com.ivansario.secureauth.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.dto.RegisterResponse;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.util.RoleEnum;

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
@Controller
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
    public ResponseEntity<AuthResponse> postMethodName(
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
     * Endpoint POST /registerAdmin - registra un nuevo administrador (rol ADMIN).
     *
     * @param requestAdminCreate datos para crear el administrador
     * @param request HTTP servlet request (se usa para IP y User-Agent)
     * @return ResponseEntity con {@link RegisterResponse} con información del nuevo administrador
     */
    @PostMapping("/registerAdmin")
    public ResponseEntity<RegisterResponse> registerAdmin(
        @Valid @RequestBody 
        CreateUserRequest requestAdminCreate,
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(
            authService.register(
                requestAdminCreate, 
                ipAddress, 
                userAgent, 
                RoleEnum.ROLE_ADMIN
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
    public ResponseEntity<Void> logout(@RequestBody RefreshTokenRequest request) {
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
    public ResponseEntity<AuthResponse> refreshToken(
        @Valid @RequestBody 
        RefreshTokenRequest refreshTokenRequest, 
        HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest, ipAddress, userAgent));
    }

}
