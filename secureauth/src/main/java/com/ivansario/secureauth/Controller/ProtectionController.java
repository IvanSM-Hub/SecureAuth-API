package com.ivansario.secureauth.Controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ivansario.secureauth.dto.protect.ProtectionIpRequest;
import com.ivansario.secureauth.dto.protect.ProtectionResponse;
import com.ivansario.secureauth.dto.protect.ProtectionUsernameRequest;
import com.ivansario.secureauth.service.interfaces.UserProtectionService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;

/**
 * REST controller for user protection operations.
 * <p>
 * Exposes endpoints to manage and inspect anti-abuse protections such as
 * temporary blocks by username or IP address and failed-attempt counters.
 * </p>
 */
@RestController
@Tag(name = "UserProtection", description = "User and IP protection management against brute-force attempts")
@RequiredArgsConstructor
@RequestMapping(path = "/api/protect/")
public class ProtectionController {

    private final UserProtectionService protectionService;

    @GetMapping("/all")
    @PreAuthorize(value = "hasRole('ADMIN')")
    @Operation(
        summary = "Get all protections",
        description = "Returns all user/IP protection records."
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "List of protections retrieved successfully",
            content = @Content(array = @ArraySchema(schema = @Schema(implementation = ProtectionResponse.class)))
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
    public ResponseEntity<List<ProtectionResponse>> getAllUserProtections() {
        return ResponseEntity.ok(protectionService.getAllUserProtections());
    }

    @GetMapping("/")
    @PreAuthorize(value = "hasRole('ADMIN')")
    @Operation(
        summary = "Get protection by username",
        description = "Returns protection details for a specific username."
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Protection retrieved successfully",
            content = @Content(schema = @Schema(implementation = ProtectionResponse.class))
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
    public ResponseEntity<ProtectionResponse> getProtectionByUsername(@RequestBody ProtectionUsernameRequest request) {
        return ResponseEntity.ok(protectionService.getUserProtectionByUsername(request));
    }

    @GetMapping("/")
    @PreAuthorize(value = "hasRole('ADMIN')")
    @Operation(
        summary = "Get protection by IP",
        description = "Returns protection details for a specific IP address."
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Protection retrieved successfully",
            content = @Content(schema = @Schema(implementation = ProtectionResponse.class))
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
    public ResponseEntity<ProtectionResponse> getProtectionByIp(@RequestBody ProtectionIpRequest request) {
        return ResponseEntity.ok(protectionService.getUserProtectionByIp(request));
    }

}
