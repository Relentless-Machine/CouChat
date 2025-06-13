package com.couchat.user.controller;

import com.couchat.user.model.User;
import com.couchat.user.service.UserService;
import com.couchat.auth.PasskeyAuthService; // For getting current user context
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
@RequestMapping("/api/users")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;
    private final PasskeyAuthService passkeyAuthService; // To get current user (placeholder)

    @Autowired
    public UserController(UserService userService, PasskeyAuthService passkeyAuthService) {
        this.userService = userService;
        this.passkeyAuthService = passkeyAuthService;
    }

    /**
     * Creates a new user. (Simplified for now)
     * In a real app, this would be part of a registration flow.
     */
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        logger.info("POST /api/users - createUser called with username: {}", user.getUsername());
        try {
            // For this stub, we assume the User object from request might not have ID/createdAt set
            // The service/repository handles ID generation for new users.
            // If user comes with an ID, save might act as upsert.
            User newUser = new User(user.getUsername()); // Use constructor that generates ID
            if (user.getPasswordHash() != null) { // Allow setting password hash if provided
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

    /**
     * Gets a user by their ID.
     */
    @GetMapping("/{userId}")
    public ResponseEntity<User> getUserById(@PathVariable String userId) {
        logger.info("GET /api/users/{} - getUserById called", userId);
        Optional<User> user = userService.findUserById(userId);
        return user.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Gets the currently authenticated user (placeholder).
     */
    @GetMapping("/me")
    public ResponseEntity<User> getCurrentUser() {
        logger.info("GET /api/users/me - getCurrentUser called");
        String currentUserId = passkeyAuthService.getLocalUserId(); // Uses placeholder logic
        if (currentUserId == null) {
            // This case should ideally not happen if placeholder init works,
            // or in real app, be protected by security context
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Optional<User> user = userService.findUserById(currentUserId);
        return user.map(ResponseEntity::ok).orElseGet(() -> {
            // This might happen if placeholder user was somehow not in DB
            logger.warn("Current user ID {} not found in database.", currentUserId);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        });
    }

    /**
     * Gets all users (for admin or testing purposes).
     */
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        logger.info("GET /api/users - getAllUsers called");
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    // TODO: Add endpoints for updating user (PUT /{userId})
    // TODO: Add endpoints for deleting user (DELETE /{userId})
    // TODO: Add endpoints for Passkey registration/login flows
}

