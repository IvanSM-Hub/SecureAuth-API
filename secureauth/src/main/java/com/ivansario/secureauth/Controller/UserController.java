package com.ivansario.secureauth.Controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ivansario.secureauth.dto.user.UserIdRequest;
import com.ivansario.secureauth.dto.user.CreateUserRequest;
import com.ivansario.secureauth.dto.user.RegisterResponse;
import com.ivansario.secureauth.dto.user.UpdateUserProfileRequest;
import com.ivansario.secureauth.dto.user.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.user.UserResponse;
import com.ivansario.secureauth.service.interfaces.UserService;
import com.ivansario.secureauth.util.RoleEnum;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.RequestBody;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;


@RestController
@Tag(name = "Users", description = "User profile, role and lifecycle management")
@RequiredArgsConstructor
@RequestMapping(path = "/api/user/")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserService userService;

    @GetMapping("/all")
    @PreAuthorize(value = "hasRole('ADMIN')")
    @Operation(
        summary = "Get all users",
        description = "Returns a list of all registered users in the system."
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "List of users retrieved successfully",
            content = @Content(array = @ArraySchema(schema = @Schema(implementation = UserResponse.class)))
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized access",
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
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/one")
    @PreAuthorize(value = "hasRole('ADMIN') or @userSecurity.isOwner(#request.id)")
    @Operation(
        summary = "Get one user by id",
        description = "Returns a user by their identifier sent in the request body."
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
        required = true,
        description = "Payload with the user id",
        content = @Content(
            mediaType = "application/json",
            schema = @Schema(implementation = UserIdRequest.class),
            examples = @ExampleObject(value = """
                {
                  \"id\": \"7f84a249-f0f6-4cf8-a464-82f6fd4aab8f\"
                }
                """)
        )
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "User retrieved successfully",
            content = @Content(schema = @Schema(implementation = UserResponse.class))
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized access",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Unauthorized"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 404,
                  "error": "Not Found",
                  "message": "User not found"
                }
                """))
        )
    })
    public ResponseEntity<UserResponse> getUser(@Valid @RequestBody UserIdRequest request) {
        return ResponseEntity.ok(userService.getUserById(request.getId()));
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
                                        "password": "Password must be between 8 and 128 characters"
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
        return ResponseEntity.ok(userService.register(requestCreateUser, 
                ipAddress, 
                userAgent, 
                RoleEnum.ROLE_USER
            )
        );
    }

    @PutMapping("/update-user")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(#request.id)")
    @Operation(
        summary = "Update user profile",
        description = "Updates a user profile; the target user id must be included in the DTO body."
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
        required = true,
        description = "Payload with user id and profile fields to update",
        content = @Content(
            mediaType = "application/json",
            schema = @Schema(implementation = UpdateUserProfileRequest.class)
        )
    )
    @ApiResponses({
                @ApiResponse(
                        responseCode = "200",
                    description = "User profile updated successfully",
                        content = @Content(schema = @Schema(implementation = UserResponse.class))
                ),
                @ApiResponse(
                        responseCode = "400",
                    description = "Invalid request data",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 400,
                                    "error": "Bad Request",
                                    "message": "Validation failed",
                                    "errors": {
                                        "email": "Email must be valid"
                                    }
                                }
                                """))
                ),
                @ApiResponse(
                        responseCode = "401",
                        description = "Unauthorized access",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 401,
                                    "error": "Unauthorized",
                                    "message": "Unauthorized"
                                }
                                """))
                ),
                @ApiResponse(
                        responseCode = "403",
                        description = "Forbidden",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 403,
                                    "error": "Forbidden",
                                    "message": "Access denied"
                                }
                                """))
                ),
                @ApiResponse(
                        responseCode = "404",
                        description = "User not found",
                        content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                                {
                                    "timestamp": "2026-05-27T10:15:30",
                                    "status": 404,
                                    "error": "Not Found",
                                    "message": "User not found"
                                }
                                """))
                )
    })
    public ResponseEntity<UserResponse> updateUserProfile(@Valid @RequestBody UpdateUserProfileRequest request) {
        return ResponseEntity.ok(userService.updateUserProfile(request));
    }
    
    @PutMapping("/update-role")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Update user role",
        description = "Updates a user's role; the target user id must be included in the DTO body."
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
        required = true,
        description = "Payload with user id and the new role",
        content = @Content(
            mediaType = "application/json",
            schema = @Schema(implementation = UpdateUserRoleRequest.class)
        )
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "User role updated successfully",
            content = @Content(schema = @Schema(implementation = UserResponse.class))
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid request data",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 400,
                  "error": "Bad Request",
                  "message": "Validation failed"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized access",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Unauthorized"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 404,
                  "error": "Not Found",
                  "message": "User not found"
                }
                """))
        )
    })
    public ResponseEntity<UserResponse> updateRoleUser(@Valid @RequestBody UpdateUserRoleRequest request) {
        return ResponseEntity.ok(userService.updateUserRole(request));
    }

    @PutMapping("/delete")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(#request.id)")
    @Operation(
        summary = "Soft delete user",
        description = "Marks a user as deleted without removing the record; user id is sent in DTO body."
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
        required = true,
        description = "Payload with the user id",
        content = @Content(
            mediaType = "application/json",
            schema = @Schema(implementation = UserIdRequest.class)
        )
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "User soft-deleted successfully",
            content = @Content(schema = @Schema(implementation = UserResponse.class))
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized access",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Unauthorized"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Forbidden",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 403,
                  "error": "Forbidden",
                  "message": "Access denied"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 404,
                  "error": "Not Found",
                  "message": "User not found"
                }
                """))
        )
    })
    public ResponseEntity<UserResponse> virtualDeleteUser(@Valid @RequestBody UserIdRequest request) {
        return ResponseEntity.ok(userService.virtualDeleteUser(request.getId()));
    }

    @PutMapping("/active")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Activate user",
        description = "Reactivates a previously disabled user; user id is sent in DTO body."
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
        required = true,
        description = "Payload with the user id",
        content = @Content(
            mediaType = "application/json",
            schema = @Schema(implementation = UserIdRequest.class)
        )
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "User activated successfully",
            content = @Content(schema = @Schema(implementation = UserResponse.class))
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized access",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Unauthorized"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 404,
                  "error": "Not Found",
                  "message": "User not found"
                }
                """))
        )
    })
    public ResponseEntity<UserResponse> activateUser(@Valid @RequestBody UserIdRequest request) {
        return ResponseEntity.ok(userService.activateUser(request.getId()));
    }

    @DeleteMapping("/permanentlyDelete")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Permanently delete user",
        description = "Permanently removes a user from the database; user id is sent in DTO body."
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
        required = true,
        description = "Payload with the user id",
        content = @Content(
            mediaType = "application/json",
            schema = @Schema(implementation = UserIdRequest.class)
        )
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "User permanently deleted successfully",
            content = @Content(schema = @Schema(implementation = Boolean.class))
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Unauthorized access",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Unauthorized"
                }
                """))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found",
            content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                {
                  "timestamp": "2026-05-27T10:15:30",
                  "status": 404,
                  "error": "Not Found",
                  "message": "User not found"
                }
                """))
        )
    })
    public ResponseEntity<Boolean> permanentlyDeleteUser(@Valid @RequestBody UserIdRequest request) {
        return ResponseEntity.ok(userService.permanentlyDeleteUser(request.getId()));
    }

}
