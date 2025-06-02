package com.couchat.security;

// 消息存储模块接口
public interface MessageStorageInterface {
    void saveMessage(String message);   // 存储消息
    String fetchMessage(int messageId); // 获取消息
    void deleteMessage(int messageId);  // 删除消息
}

