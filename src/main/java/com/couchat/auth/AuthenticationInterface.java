package com.couchat.auth;

// 用户认证模块接口
public interface AuthenticationInterface {
    void authenticateUser(String username, String password);  // 用户名密码认证
    void authenticateWithOAuth(String oauthToken);           // 第三方OAuth认证
    void bindDevicePasskey(String deviceId, String passkey); // 设备绑定
}

