package com.couchat.security;

// 消息存储模块接口
public interface MessageStorageInterface {
    int saveMessage(String message);   // 存储消息, 返回消息ID
    String fetchMessage(int messageId); // 获取消息
    void deleteMessage(int messageId);  // 删除消息
}
