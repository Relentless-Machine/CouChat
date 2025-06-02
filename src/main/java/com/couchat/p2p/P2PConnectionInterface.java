package com.couchat.p2p;

// P2P连接管理模块接口
public interface P2PConnectionInterface {
    void initiateConnection(String peerAddress);  // 建立连接
    void handleReconnect();                       // 断线重连
    void sendMessage(String message);             // 发送消息
    String receiveMessage();                      // 接收消息
}

