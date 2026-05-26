package com.ivansario.secureauth.Controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ivansario.secureauth.dto.UpdateUserProfileRequest;
import com.ivansario.secureauth.dto.UpdateUserRoleRequest;
import com.ivansario.secureauth.dto.UserResponse;
import com.ivansario.secureauth.service.UserServiceImpl;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.web.bind.annotation.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
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
@Tag(name = "Users", description = "CRUD Operations for user management")
@RequiredArgsConstructor
@RequestMapping(path = "/api/user/")
public class UserController {

    private final UserServiceImpl userService;

    @GetMapping("/all")
    @PreAuthorize(value = "hasRole('ADMIN')")
    @Operation(
        summary = "Get all users",
        description = "Returns a list of all registered users in the system."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "List of users retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized access")
    })
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{userId}")
    @PreAuthorize(value = "hasRole('ADMIN')")
    @Operation(
        summary = "Get one user by id",
        description = "Returns a user."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized access")
    })
    public ResponseEntity<UserResponse> getUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    @PutMapping("/update/{userId}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(#userId)")
    @Operation(
        summary = "Put to update a user beening the admin or the owner user",
        description = "Returns a user."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User updated successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized access")
    })
    public ResponseEntity<UserResponse> updateUser(@PathVariable String userId, @RequestBody UpdateUserProfileRequest request) {
        return ResponseEntity.ok(userService.updateUserProfile(userId, request));
    }
    
    @PutMapping("/role/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Put to change a user role to a specific role",
        description = "Returns a user."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User change role successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized access")
    })
    public ResponseEntity<UserResponse> updateRoleUser(@PathVariable String userId, @RequestBody UpdateUserRoleRequest request) {
        return ResponseEntity.ok(userService.updateUserRole(userId, request));
    }

    @PutMapping("/delete/{userId}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(#userId)")
    @Operation(
        summary = "Virtual delete a user",
        description = "Returns a user."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Virtual delete a user"),
        @ApiResponse(responseCode = "401", description = "Unauthorized access")
    })
    public ResponseEntity<UserResponse> virtualDeleteUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.virtualDeleteUser(userId));
    }

    @PutMapping("/active/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Activate a user",
        description = "Returns a user."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Activate a user"),
        @ApiResponse(responseCode = "401", description = "Unauthorized access")
    })
    public ResponseEntity<UserResponse> activateUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.activateUser(userId));
    }

    @DeleteMapping("/permanentlyDelete/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Virtual delete a user",
        description = "Returns a user."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Virtual delete a user"),
        @ApiResponse(responseCode = "401", description = "Unauthorized access")
    })
    public ResponseEntity<UserResponse> permanentlyDeleteUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.permanentlyDeleteUser(userId));
    }

}
