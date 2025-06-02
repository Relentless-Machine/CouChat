package com.couchat.group;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class GroupManagerTest {

    private static final Logger logger = LoggerFactory.getLogger(GroupManagerTest.class);
    private GroupManager groupManager;

    @BeforeEach
    void setUp() {
        groupManager = new GroupManager();
        groupManager.clearAllGroups(); // Clear state before each test
        logger.info("GroupManager initialized and cleared for test.");
    }

    @Test
    void testCreateGroup_Success() {
        String groupName = "Test Group Alpha";
        List<String> members = Arrays.asList("user1", "user2");
        logger.info("Testing group creation: Name='{}', Members={}", groupName, members);

        String createdGroupId = groupManager.createGroup(groupName, members);

        assertNotNull(createdGroupId, "Group ID should not be null after creation.");
        assertTrue(groupManager.groupExists(createdGroupId), "Group should exist after creation.");

        GroupManager.Group createdGroup = groupManager.getGroupById(createdGroupId);
        assertNotNull(createdGroup, "Group object should be retrievable.");
        assertEquals(groupName, createdGroup.groupName, "Group name should match.");
        assertEquals(members.size(), createdGroup.memberIds.size(), "Member count should match.");
        assertTrue(createdGroup.memberIds.containsAll(members), "All initial members should be in the group.");
        logger.info("Group '{}' created successfully with ID: {}", groupName, createdGroupId);
    }

    @Test
    void testCreateGroup_NullName() {
        logger.info("Testing group creation with null name.");
        String groupId = groupManager.createGroup(null, Arrays.asList("user1"));
        assertNull(groupId, "Group ID should be null when creation fails due to null name.");
    }

    @Test
    void testCreateGroup_EmptyName() {
        logger.info("Testing group creation with empty name.");
        String groupId = groupManager.createGroup("   ", Arrays.asList("user1"));
        assertNull(groupId, "Group ID should be null for empty name.");
    }

    @Test
    void testCreateGroup_NullMembers() {
        logger.info("Testing group creation with null member list.");
        String groupId = groupManager.createGroup("Null Member Group", null);
        assertNull(groupId, "Group ID should be null for null members.");
    }

    @Test
    void testCreateGroup_EmptyMembers() {
        logger.info("Testing group creation with empty member list.");
        String groupId = groupManager.createGroup("Empty Member Group", Collections.emptyList());
        assertNull(groupId, "Group ID should be null for empty member list.");
    }

    @Test
    void testAddMemberToGroup_Success() {
        String groupName = "Membership Test Group";
        List<String> initialMembers = new ArrayList<>(Arrays.asList("memberA"));
        String groupId = groupManager.createGroup(groupName, initialMembers);
        assertNotNull(groupId, "Test group setup failed to return a group ID.");

        String newMember = "memberB";
        logger.info("Testing adding member '{}' to group ID '{}'", newMember, groupId);
        groupManager.addMemberToGroup(groupId, newMember);

        List<String> membersAfterAdd = groupManager.getGroupMembers(groupId);
        assertEquals(2, membersAfterAdd.size(), "Member count should be 2 after adding a new member.");
        assertTrue(membersAfterAdd.contains(newMember), "New member should be in the group.");
        assertTrue(membersAfterAdd.contains("memberA"), "Initial member should still be in the group.");
    }

    @Test
    void testAddMemberToGroup_GroupNotFound() {
        logger.info("Testing adding member to a non-existent group.");
        groupManager.addMemberToGroup("nonExistentGroupId_XYZ", "userX");
        assertNull(groupManager.getGroupById("nonExistentGroupId_XYZ"));
    }

    @Test
    void testAddMemberToGroup_NullGroupId() {
        groupManager.addMemberToGroup(null, "userX");
        assertNull(groupManager.getGroupById(null));
    }

    @Test
    void testAddMemberToGroup_NullMemberId() {
        String groupName = "Null Member ID Test Group";
        List<String> initialMembers = Arrays.asList("member1");
        String groupId = groupManager.createGroup(groupName, initialMembers);
        assertNotNull(groupId);
        groupManager.addMemberToGroup(groupId, null);
        assertEquals(1, groupManager.getGroupMembers(groupId).size(), "Member count should remain 1.");
    }

    @Test
    void testAddMemberToGroup_EmptyMemberId() {
        String groupName = "Empty Member ID Test Group";
        List<String> initialMembers = Arrays.asList("member1");
        String groupId = groupManager.createGroup(groupName, initialMembers);
        assertNotNull(groupId);
        groupManager.addMemberToGroup(groupId, "  ");
        assertEquals(1, groupManager.getGroupMembers(groupId).size(), "Member count should remain 1.");
    }

    @Test
    void testAddMemberToGroup_MemberAlreadyExists() {
        String existingMember = "memberAlpha";
        String groupName = "Existing Member Test Group";
        List<String> initialMembers = Arrays.asList(existingMember);
        String groupId = groupManager.createGroup(groupName, initialMembers);
        assertNotNull(groupId);

        logger.info("Testing adding an existing member '{}' to group ID '{}'", existingMember, groupId);
        groupManager.addMemberToGroup(groupId, existingMember);
        List<String> members = groupManager.getGroupMembers(groupId);
        assertEquals(1, members.size(), "Member count should remain 1 if member already exists.");
    }

    @Test
    void testGetGroupMessages_Success_WithMessages() {
        String groupName = "Message Test Group";
        List<String> initialMembers = Arrays.asList("userMsg1");
        String groupId = groupManager.createGroup(groupName, initialMembers);
        assertNotNull(groupId);

        logger.info("Testing getting messages for group ID '{}'", groupId);
        groupManager.addMessageToGroupStore(groupId, "Hello Group Members!");
        groupManager.addMessageToGroupStore(groupId, "This is another test message.");

        List<String> messages = groupManager.getGroupMessages(groupId);
        assertNotNull(messages, "Message list should not be null.");
        assertEquals(2, messages.size(), "Should retrieve 2 messages.");
        assertTrue(messages.contains("Hello Group Members!"));
        assertTrue(messages.contains("This is another test message."));
    }

    @Test
    void testGetGroupMessages_Success_NoMessages() {
        String groupName = "No Message Test Group";
        List<String> initialMembers = Arrays.asList("userNoMsg");
        String groupId = groupManager.createGroup(groupName, initialMembers);
        assertNotNull(groupId);
        logger.info("Testing getting messages for group ID '{}' which has no messages.", groupId);
        List<String> messages = groupManager.getGroupMessages(groupId);
        assertNotNull(messages, "Message list should not be null.");
        assertTrue(messages.isEmpty(), "Message list should be empty if no messages were added.");
    }

    @Test
    void testGetGroupMessages_GroupNotFound() {
        logger.info("Testing getting messages for a non-existent group.");
        List<String> messages = groupManager.getGroupMessages("nonExistentGroupId_ABC");
        assertNotNull(messages, "Message list should not be null (should be empty).");
        assertTrue(messages.isEmpty(), "Message list should be empty for a non-existent group.");
    }

    @Test
    void testGetGroupMessages_NullGroupId() {
        List<String> messages = groupManager.getGroupMessages(null);
        assertTrue(messages.isEmpty(), "Messages for null group ID should be empty.");
    }

    @Test
    void addMessageToGroupStore_NullMessage() {
        String groupName = "Null Message Add Test";
        List<String> initialMembers = Arrays.asList("user1");
        String groupId = groupManager.createGroup(groupName, initialMembers);
        assertNotNull(groupId);
        groupManager.addMessageToGroupStore(groupId, null);
        assertTrue(groupManager.getGroupMessages(groupId).isEmpty(), "No message should be added if it's null.");
    }
}

