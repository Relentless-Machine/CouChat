package com.couchat.security;

// 消息加密模块接口
public interface MessageEncryptionInterface {
    String encryptMessage(String message) throws Exception;  // 加密消息
    String decryptMessage(String encryptedMessage) throws Exception; // 解密消息
}

