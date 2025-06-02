package com.couchat.group;

import java.util.List;

// 群组管理模块接口
public interface GroupManagementInterface {
    void createGroup(String groupName, List<String> memberIds); // 创建群组
    void addMemberToGroup(String groupId, String memberId);   // 添加成员到群组
    List<String> getGroupMessages(String groupId);             // 获取群组消息
}

