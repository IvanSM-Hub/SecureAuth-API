package com.ivansario.secureauth.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

import com.ivansario.secureauth.dto.AuthResponse;
import com.ivansario.secureauth.dto.CreateUserRequest;
import com.ivansario.secureauth.dto.InitialAdminLoginRequest;
import com.ivansario.secureauth.dto.LoginRequest;
import com.ivansario.secureauth.dto.NewPasswordUserRequest;
import com.ivansario.secureauth.dto.RefreshTokenRequest;
import com.ivansario.secureauth.dto.RegisterResponse;
import com.ivansario.secureauth.service.interfaces.AuthService;
import com.ivansario.secureauth.util.RoleEnum;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


/**
 * REST controller for authentication operations.
 * <p>
 * Exposes endpoints for sign in, registration, sign out, and token refresh.
 * </p>
 */
@RestController
@Tag(name = "Authentication", description = "Authentication, registration and token lifecycle operations")
@RequiredArgsConstructor
@RequestMapping(path = "/api/auth/")
public class AuthController {

    private final AuthService authService;

    /**
     * POST /login endpoint - authenticates the user and returns tokens.
     *
     * @param loginRequest request with credentials (username, password)
     * @param request HTTP servlet request used to capture IP and User-Agent
     * @return ResponseEntity with {@link AuthResponse} containing the access and refresh tokens
     */
    @PostMapping("/login")
    @Operation(
        summary = "Sign in",
        description = "Authenticates a user and returns an access token, refresh token, and basic profile data."
    )
    @ApiResponses({
                @ApiResponse(
                        responseCode = "200",
                description = "Authentication successful",
                        content = @Content(schema = @Schema(implementation = AuthResponse.class))
                ),
                @ApiResponse(
                        responseCode = "400",
                description = "Invalid login data",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 400,
                                    "error": "Bad Request",
                                    "message": "Validation failed",
                                    "errors": {
                                        "username": "Username or email is required",
                                        "password": "Password is required"
                                    }
                                }
                                """))
                ),
                @ApiResponse(
                        responseCode = "401",
                    description = "Invalid credentials",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 401,
                                    "error": "Unauthorized",
                                    "message": "Invalid credentials"
                                }
                                """))
                )
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
     * POST /admin-init endpoint - authenticates the initial admin user setup.
     *
     * This endpoint is intended ONLY for the initial bootstrap of the system
     * or controlled administrative initialization scenarios.
     *
     * It allows authentication of the initial admin user even when relaxed
     * password constraints are applied during system setup.
     *
     * @param loginRequest request with credentials (username, password)
     * @param request      HTTP servlet request used to capture IP and User-Agent
     * @return ResponseEntity with {@link AuthResponse} containing the access and
     *         refresh tokens
     */
    @PostMapping("/admin-init")
    @Operation(summary = "Initial admin authentication", description = """
            Authenticates the initial administrator user during system bootstrap.

            This endpoint is intended for first-time setup only and should NOT be exposed
            in normal production authentication flows.

            It returns an access token, refresh token, and basic profile data for the admin user.
            """)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Initial admin authentication successful", content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid login data", content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                        {
                            "timestamp": "2026-05-27T10:15:30",
                            "status": 400,
                            "error": "Bad Request",
                            "message": "Validation failed",
                            "errors": {
                                "username": "Username or email is required",
                                "password": "Password is required"
                            }
                        }
                    """))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials", content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                        {
                            "timestamp": "2026-05-27T10:15:30",
                            "status": 401,
                            "error": "Unauthorized",
                            "message": "Invalid credentials"
                        }
                    """))),
            @ApiResponse(responseCode = "403", description = "Forbidden - endpoint not allowed in production context", content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                        {
                            "timestamp": "2026-05-27T10:15:30",
                            "status": 403,
                            "error": "Forbidden",
                            "message": "Admin initialization endpoint is disabled or not allowed"
                        }
                    """)))
    })
    public ResponseEntity<AuthResponse> initialAdminLogin(
            @Valid @RequestBody InitialAdminLoginRequest loginRequest,
            HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return ResponseEntity.ok(authService.initialAdminLogin(loginRequest, ipAddress, userAgent));
    }

    /**
     * POST /register endpoint - creates a new user with the USER role.
     *
     * @param requestCreateUser user creation data
     * @param request HTTP servlet request used to capture IP and User-Agent
     * @return ResponseEntity with {@link RegisterResponse} containing the new user's information
     */
    @PostMapping("/register")
    @Operation(
        summary = "Register user",
        description = "Creates a new user with the ROLE_USER role and returns the registered data."
    )
    @ApiResponses({
                @ApiResponse(
                        responseCode = "200",
                description = "User registered successfully",
                        content = @Content(schema = @Schema(implementation = RegisterResponse.class))
                ),
                @ApiResponse(
                        responseCode = "400",
                description = "Invalid registration data",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 400,
                                    "error": "Bad Request",
                                    "message": "Validation failed",
                                    "errors": {
                                        "email": "Email is required",
                                        "password": "Password must be between 8 and 255 characters"
                                    }
                                }
                                """))
                ),
                @ApiResponse(
                        responseCode = "409",
                    description = "User already exists",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 409,
                                    "error": "Conflict",
                                    "message": "User already exists"
                                }
                                """))
                )
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
     * POST /logout endpoint - invalidates a refresh token and revokes the session.
     *
     * @param request request containing the refresh token to revoke
     * @return empty ResponseEntity with status 204 when the operation succeeds
     */
    @PostMapping("/logout")
    @Operation(
        summary = "Sign out",
        description = "Revokes the provided refresh token and marks the user's session as revoked."
    )
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Session closed successfully"),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid refresh token",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 400,
                  "error": "Bad Request",
                  "message": "Invalid refresh token"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Unauthorized"
                }
                """))
        )
    })
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request);
        return ResponseEntity.noContent().build();
    }

    /**
     * POST /refresh endpoint - renews access and refresh tokens using a valid refresh token.
     *
     * @param refreshTokenRequest request containing the current refresh token
     * @param request HTTP servlet request used to capture IP and User-Agent
     * @return ResponseEntity with {@link AuthResponse} containing the new tokens
     */
    @PostMapping("/refresh")
    @Operation(
        summary = "Refresh tokens",
        description = "Exchanges a valid refresh token for a new access token and refresh token."
    )
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Tokens renovados correctamente",
            content = @Content(schema = @Schema(implementation = AuthResponse.class))
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid or expired refresh token",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 400,
                  "error": "Bad Request",
                  "message": "Invalid refresh token"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Unauthorized"
                }
                """))
        )
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
        summary = "Change password",
        description = "Updates the authenticated user's password and returns renewed tokens."
    )
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
                @ApiResponse(
                        responseCode = "200",
                    description = "Password updated successfully",
                        content = @Content(schema = @Schema(implementation = AuthResponse.class))
                ),
                @ApiResponse(
                        responseCode = "400",
                    description = "Invalid password change data",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 400,
                                    "error": "Bad Request",
                                    "message": "Validation failed",
                                    "errors": {
                                        "confirmationPassword": "Password confirmation is required"
                                    }
                                }
                                """))
                ),
                @ApiResponse(
                        responseCode = "401",
                    description = "Unauthorized",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 401,
                                    "error": "Unauthorized",
                                    "message": "Unauthorized"
                                }
                                """))
                )
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
