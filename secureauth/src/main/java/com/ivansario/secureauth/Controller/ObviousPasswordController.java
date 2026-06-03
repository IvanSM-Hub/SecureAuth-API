package com.ivansario.secureauth.Controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.ivansario.secureauth.dto.protect.ObviousPasswordIdRequest;
import com.ivansario.secureauth.entity.ObviousPassword;
import com.ivansario.secureauth.service.interfaces.ObviousPasswordService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@Tag(name = "ObviousPasswords", description = "List of obvious passwords that system should not allow")
@RequiredArgsConstructor
@RequestMapping(path = "/api/obviousPasswords/")
@SecurityRequirement(name = "bearerAuth")
public class ObviousPasswordController {

	private final ObviousPasswordService obviousPasswordService;
    
	@GetMapping("/all")
	@PreAuthorize("hasRole('ADMIN')")
	@Operation(summary = "Get all obvious passwords", description = "Returns the current list of rejected obvious passwords.")
	@ApiResponses({
		@ApiResponse(responseCode = "200", description = "List retrieved successfully"),
		@ApiResponse(responseCode = "401", description = "Unauthorized access"),
		@ApiResponse(responseCode = "403", description = "Forbidden")
	})
	public ResponseEntity<List<ObviousPassword>> getAllObviousPasswords() {
		return ResponseEntity.ok(obviousPasswordService.findAllObviousPasswords());
	}

	@PostMapping("/one")
	@PreAuthorize("hasRole('ADMIN')")
	@Operation(summary = "Get one obvious password by id", description = "Returns one obvious password entry by its identifier sent in the request body.")
	@io.swagger.v3.oas.annotations.parameters.RequestBody(
		required = true,
		description = "Payload with the obvious password id",
		content = @Content(
			mediaType = "application/json",
			schema = @Schema(implementation = ObviousPasswordIdRequest.class),
			examples = @ExampleObject(value = """
				{
				  \"id\": \"7f84a249-f0f6-4cf8-a464-82f6fd4aab8f\"
				}
				""")
		)
	)
	@ApiResponses({
		@ApiResponse(responseCode = "200", description = "Password entry retrieved successfully"),
		@ApiResponse(responseCode = "401", description = "Unauthorized access"),
		@ApiResponse(responseCode = "403", description = "Forbidden"),
		@ApiResponse(responseCode = "404", description = "Password entry not found")
	})
	public ResponseEntity<ObviousPassword> getObviousPassword(@Valid @RequestBody ObviousPasswordIdRequest request) {
		return ResponseEntity.ok(obviousPasswordService.findObviousPasswordById(request));
	}

	@PostMapping("/create")
	@PreAuthorize("hasRole('ADMIN')")
	@Operation(summary = "Create an obvious password entry", description = "Stores one password value in the obvious-passwords table.")
	@ApiResponses({
		@ApiResponse(responseCode = "201", description = "Password entry created successfully"),
		@ApiResponse(responseCode = "400", description = "Invalid request data"),
		@ApiResponse(responseCode = "401", description = "Unauthorized access"),
		@ApiResponse(responseCode = "403", description = "Forbidden")
	})
	public ResponseEntity<ObviousPassword> createObviousPassword(@RequestBody ObviousPassword obviousPassword) {
		return ResponseEntity.status(201).body(obviousPasswordService.createObviousPassword(obviousPassword));
	}

	@PostMapping("/bulk")
	@PreAuthorize("hasRole('ADMIN')")
	@Operation(summary = "Bulk create obvious passwords", description = "Stores multiple password values in one request.")
	@ApiResponses({
		@ApiResponse(responseCode = "201", description = "Password entries created successfully"),
		@ApiResponse(responseCode = "400", description = "Invalid request data"),
		@ApiResponse(responseCode = "401", description = "Unauthorized access"),
		@ApiResponse(responseCode = "403", description = "Forbidden")
	})
	public ResponseEntity<List<ObviousPassword>> bulkCreateObviousPasswords(@RequestBody List<ObviousPassword> obviousPasswords) {
		return ResponseEntity.status(201).body(obviousPasswordService.bulkSave(obviousPasswords));
	}

	@DeleteMapping("/delete")
	@PreAuthorize("hasRole('ADMIN')")
	@Operation(summary = "Delete an obvious password entry", description = "Removes one obvious password value by its identifier sent in the request body.")
	@io.swagger.v3.oas.annotations.parameters.RequestBody(
		required = true,
		description = "Payload with the obvious password id",
		content = @Content(
			mediaType = "application/json",
			schema = @Schema(implementation = ObviousPasswordIdRequest.class)
		)
	)
	@ApiResponses({
		@ApiResponse(responseCode = "200", description = "Password entry deleted successfully"),
		@ApiResponse(responseCode = "401", description = "Unauthorized access"),
		@ApiResponse(responseCode = "403", description = "Forbidden"),
		@ApiResponse(responseCode = "404", description = "Password entry not found")
	})
	public ResponseEntity<Boolean> deleteObviousPassword(@Valid @RequestBody ObviousPasswordIdRequest request) {
		return ResponseEntity.ok(obviousPasswordService.deleteObviousPassword(request));
	}

}
