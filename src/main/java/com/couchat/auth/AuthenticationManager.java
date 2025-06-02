package com.couchat.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

// TODO: Implement OAuth 2.0 client flow for Microsoft & Google
// TODO: Implement device passkey generation, storage (securely), and validation
// TODO: Integrate with a database (SQLite as per SDD) for storing user and device information

public class AuthenticationManager implements AuthenticationInterface {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationManager.class);
    private static final String DB_URL = "jdbc:sqlite:couchat_storage.db"; // Same DB as MessageSecurityManager

    private final Map<String, Boolean> loggedInUsers = new HashMap<>(); // username -> isLoggedIn (placeholder)

    public AuthenticationManager() {
        initializeDatabaseTables();
        addUserToDbIfNotExists("testuser", "password
