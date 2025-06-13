package com.couchat.group.service;

import com.couchat.group.model.Group;
import com.couchat.repository.GroupRepository;
import com.couchat.repository.UserRepository;
import com.couchat.user.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service layer for group-related operations.
 */
@Service
public class GroupService {

    private static final Logger logger = LoggerFactory.getLogger(GroupService.class);
    private final GroupRepository groupRepository;
    private final UserRepository userRepository; // For fetching user details for members

    @Autowired
    public GroupService(GroupRepository groupRepository, UserRepository userRepository) {
        this.groupRepository = groupRepository;
        this.userRepository = userRepository;
    }

    /**
     * Creates a new group.
     *
     * @param groupName The name of the group.
     * @param creatorUserId The ID of the user creating the group.
     * @param initialMemberIds List of user IDs to add as initial members (creator is added automatically).
     * @return The created group.
     */
    @Transactional
    public Group createGroup(String groupName, String creatorUserId, List<String> initialMemberIds) {
        logger.info("GroupService.createGroup called by user: {} for group name: {}", creatorUserId, groupName);
        User creator = userRepository.findById(creatorUserId)
                .orElseThrow(() -> new IllegalArgumentException("Creator user not found: " + creatorUserId));

        Group group = new Group(groupName, creatorUserId);
        Group savedGroup = groupRepository.save(group);

        // Add creator as the first member (typically an ADMIN)
        groupRepository.addMember(savedGroup.getGroupId(), creatorUserId, "ADMIN");

        if (initialMemberIds != null) {
            for (String memberId : initialMemberIds) {
                if (!memberId.equals(creatorUserId)) { // Avoid adding creator twice
                    userRepository.findById(memberId)
                        .ifPresentOrElse(
                            user -> groupRepository.addMember(savedGroup.getGroupId(), memberId, "MEMBER"),
                            () -> logger.warn("User not found while adding to group: {}", memberId)
                        );
                }
            }
        }
        return savedGroup;
    }

    /**
     * Finds a group by its ID.
     *
     * @param groupId The group ID.
     * @return Optional of Group.
     */
    public Optional<Group> findGroupById(String groupId) {
        logger.info("GroupService.findGroupById called for groupId: {}", groupId);
        return groupRepository.findById(groupId);
    }

    /**
     * Adds a member to a group.
     *
     * @param groupId The group ID.
     * @param userId The user ID of the member to add.
     * @param adderUserId The user ID of the person performing the add action (for permission checks).
     * @return true if successful.
     */
    @Transactional
    public boolean addMemberToGroup(String groupId, String userId, String adderUserId) {
        logger.info("GroupService.addMemberToGroup called for group: {}, user: {}, adder: {}", groupId, userId, adderUserId);
        // TODO: Add permission check: only admin or existing members (depending on policy) can add
        // if (!groupRepository.isUserMemberOfGroup(groupId, adderUserId)) {
        //    throw new SecurityException("User " + adderUserId + " is not authorized to add members to group " + groupId);
        // }
        userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User to add not found: " + userId));
        groupRepository.findById(groupId).orElseThrow(() -> new IllegalArgumentException("Group not found: " + groupId));
        return groupRepository.addMember(groupId, userId, "MEMBER");
    }

    /**
     * Removes a member from a group.
     *
     * @param groupId The group ID.
     * @param userId The user ID of the member to remove.
     * @param removerUserId The user ID of the person performing the remove action.
     * @return true if successful.
     */
    @Transactional
    public boolean removeMemberFromGroup(String groupId, String userId, String removerUserId) {
        logger.info("GroupService.removeMemberFromGroup called for group: {}, user: {}, remover: {}", groupId, userId, removerUserId);
        // TODO: Add permission check: admin can remove anyone, member can remove self.
        return groupRepository.removeMember(groupId, userId);
    }

    /**
     * Retrieves members of a group.
     * (This is a simplified version, a more complex one might return User objects with roles)
     *
     * @param groupId The group ID.
     * @return List of user IDs.
     */
    public List<String> getGroupMemberIds(String groupId) {
        logger.info("GroupService.getGroupMemberIds called for groupId: {}", groupId);
        return groupRepository.findMemberIdsByGroupId(groupId);
    }

    /**
     * Retrieves groups for a user.
     * @param userId The user ID.
     * @param limit Page size.
     * @param offset Page offset.
     * @return List of groups.
     */
    public List<Group> getGroupsForUser(String userId, int limit, int offset) {
        logger.info("GroupService.getGroupsForUser called for userId: {}", userId);
        return groupRepository.findAllByMemberUserId(userId, limit, offset);
    }

    /**
     * Deletes a group.
     * @param groupId The group ID.
     * @param userId The user ID of the person attempting deletion (for permission checks).
     * @return true if successful.
     */
    @Transactional
    public boolean deleteGroup(String groupId, String userId) {
        logger.info("GroupService.deleteGroup called for groupId: {} by user: {}", groupId, userId);
        Group group = groupRepository.findById(groupId)
            .orElseThrow(() -> new IllegalArgumentException("Group not found: " + groupId));
        // TODO: Add permission check: only group creator/admin can delete.
        // if (!group.getCreatedBy().equals(userId)) {
        //    throw new SecurityException("User " + userId + " is not authorized to delete group " + groupId);
        // }
        // Cascading deletes in DB should handle group_members and conversations linked to this group_id.
        return groupRepository.deleteById(groupId);
    }
}

