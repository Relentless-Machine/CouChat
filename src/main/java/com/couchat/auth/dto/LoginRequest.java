package com.couchat.auth.dto;

public class LoginRequest {
    private String username;
    private String deviceName; // Optional: for associating a new device during login

    // Getters and setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }
}

