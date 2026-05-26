package com.ivansario.secureauth.Controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ivansario.secureauth.dto.UpdateUserRequest;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;


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

    @PostMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(#userId)")
    @Operation(
        summary = "Post to update a user beening the admin or the owner user",
        description = "Returns a user."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User updated successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized access")
    })
    public ResponseEntity<UserResponse> updateUser(@PathVariable String userId, @RequestBody UpdateUserRequest request) {
        return ResponseEntity.ok(userService.updateUser(userId, request));
    }
    

}
