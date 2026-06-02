package com.ivansario.secureauth.Controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ivansario.secureauth.dto.user.UpdateUserProfileRequest;
import com.ivansario.secureauth.dto.user.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.user.UserResponse;
import com.ivansario.secureauth.service.interfaces.UserService;

import io.swagger.v3.oas.annotations.Operation;
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
import org.springframework.web.bind.annotation.PathVariable;
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

    @GetMapping("/{userId}")
    @PreAuthorize(value = "hasRole('ADMIN') or @userSecurity.isOwner(#userId)")
    @Operation(
        summary = "Get one user by id",
        description = "Returns a user by their identifier."
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
    public ResponseEntity<UserResponse> getUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    @PutMapping("/update/{userId}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(#userId)")
    @Operation(
        summary = "Update user profile",
        description = "Updates a user when the caller is an admin or the owner of the account."
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
    public ResponseEntity<UserResponse> updateUserProfile(@PathVariable String userId, @Valid @RequestBody UpdateUserProfileRequest request) {
        return ResponseEntity.ok(userService.updateUserProfile(userId, request));
    }
    
    @PutMapping("/role/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Update user role",
        description = "Updates a user's role."
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
    public ResponseEntity<UserResponse> updateRoleUser(@PathVariable String userId, @Valid @RequestBody UpdateUserRoleRequest request) {
        return ResponseEntity.ok(userService.updateUserRole(userId, request));
    }

    @PutMapping("/delete/{userId}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(#userId)")
    @Operation(
        summary = "Soft delete user",
        description = "Marks a user as deleted without removing the record."
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
    public ResponseEntity<UserResponse> virtualDeleteUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.virtualDeleteUser(userId));
    }

    @PutMapping("/active/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Activate user",
        description = "Reactivates a previously disabled user."
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
    public ResponseEntity<UserResponse> activateUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.activateUser(userId));
    }

    @DeleteMapping("/permanentlyDelete/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Permanently delete user",
        description = "Permanently removes a user from the database."
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
    public ResponseEntity<Boolean> permanentlyDeleteUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.permanentlyDeleteUser(userId));
    }

}
