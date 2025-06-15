package com.couchat.user.controller;

import com.couchat.user.model.User;
import com.couchat.user.service.UserService;
import com.couchat.auth.PasskeyAuthService;
import com.couchat.auth.dto.LoginRequest;
import com.couchat.auth.dto.RegistrationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * REST controller for user-related operations.
 * Provides basic CRUD endpoints for users.
 */
@RestController
// Changed base request mapping to /api/auth for auth-related endpoints
// User-specific data endpoints can remain under /api/users if needed, or be consolidated.
@RequestMapping("/api/auth")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService; // Still useful for fetching user details
    private final PasskeyAuthService passkeyAuthService;

    @Autowired
    public UserController(UserService userService, PasskeyAuthService passkeyAuthService) {
        this.userService = userService;
        this.passkeyAuthService = passkeyAuthService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegistrationRequest registrationRequest) {
        logger.info("POST /api/auth/register - called with username: {}", registrationRequest.getUsername());
        if (registrationRequest.getUsername() == null || registrationRequest.getUsername().trim().isEmpty()) {
            return ResponseEntity.badRequest().body("Username cannot be empty.");
        }
        try {
            Optional<User> newUserOpt = passkeyAuthService.registerNewUserAndDevice(
                    registrationRequest.getUsername(),
                    registrationRequest.getDeviceName()
            );
            if (newUserOpt.isPresent()) {
                return ResponseEntity.status(HttpStatus.CREATED).body(newUserOpt.get());
            } else {
                // This could be due to username conflict or other registration rule violation in service
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Registration failed. Username might be taken or device already registered under different terms.");
            }
        } catch (Exception e) {
            logger.error("Unexpected error during user registration for username {}: {}", registrationRequest.getUsername(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred during registration.");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest) {
        logger.info("POST /api/auth/login - called with username: {}", loginRequest.getUsername());
        if (loginRequest.getUsername() == null || loginRequest.getUsername().trim().isEmpty()) {
            return ResponseEntity.badRequest().body("Username cannot be empty.");
        }
        try {
            Optional<User> userOpt = passkeyAuthService.loginUserAndAssociateDevice(
                    loginRequest.getUsername(),
                    loginRequest.getDeviceName()
            );
            if (userOpt.isPresent()) {
                return ResponseEntity.ok(userOpt.get());
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed. Invalid username or device association issue.");
            }
        } catch (Exception e) {
            logger.error("Unexpected error during user login for username {}: {}", loginRequest.getUsername(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred during login.");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser() {
        logger.info("POST /api/auth/logout - called");
        String userId = passkeyAuthService.getLocalUserId();
        if (userId == null) {
             // Should not happen if logout is called by an authenticated client, but good to check.
            logger.warn("Logout called, but no user was authenticated according to PasskeyAuthService.");
            return ResponseEntity.ok("No active session to log out or already logged out.");
        }
        try {
            passkeyAuthService.logout();
            return ResponseEntity.ok("Logout successful.");
        } catch (Exception e) {
            logger.error("Error during logout for user ID {}: {}", userId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred during logout.");
        }
    }

    @GetMapping("/users/me") // Kept under /users for now, or could be /api/auth/me
    public ResponseEntity<User> getCurrentUser() {
        logger.info("GET /api/auth/users/me - getCurrentUser called");
        if (!passkeyAuthService.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String currentUserId = passkeyAuthService.getLocalUserId();
        // No need to check currentUserId for null again if isAuthenticated is true and logic is sound.
        Optional<User> user = userService.findUserById(currentUserId);
        return user.map(ResponseEntity::ok).orElseGet(() -> {
            logger.error("Authenticated user ID {} not found in database. Data inconsistency?", currentUserId);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null); // Or a specific error DTO
        });
    }

    // The following endpoints are more user-management specific and might live in a separate AdminController
    // or stay here if user listing/lookup is a general feature.
    // For now, keeping them but commenting out the direct POST /api/users for creation.

    /*
    @PostMapping // This was the old createUser, replaced by /register
    public ResponseEntity<User> createUser(@RequestBody User user) {
        logger.info("POST /api/users - createUser called with username: {}", user.getUsername());
        try {
            User newUser = new User(user.getUsername());
            if (user.getPasswordHash() != null) {
                newUser.setPasswordHash(user.getPasswordHash());
            }
            User savedUser = userService.registerOrUpdateUser(newUser);
            return ResponseEntity.status(HttpStatus.CREATED).body(savedUser);
        } catch (IllegalArgumentException e) {
            logger.error("Error creating user: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            logger.error("Unexpected error creating user", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    */

    @GetMapping("/users/{userId}") // Path adjusted relative to /api/auth or could be /api/users/{userId}
    public ResponseEntity<User> getUserById(@PathVariable String userId) {
        logger.info("GET /api/auth/users/{} - getUserById called", userId);
        Optional<User> user = userService.findUserById(userId);
        return user.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/users") // Path adjusted relative to /api/auth or could be /api/users
    public ResponseEntity<List<User>> getAllUsers() {
        logger.info("GET /api/auth/users - getAllUsers called");
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }
}

