package com.couchat.group.controller;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.group.model.Group;
import com.couchat.group.service.GroupService;
import com.couchat.user.model.User; // For potential use in DTOs or richer responses
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * REST controller for group-related operations.
 */
@RestController
@RequestMapping("/api/groups")
public class GroupController {

    private static final Logger logger = LoggerFactory.getLogger(GroupController.class);
    private final GroupService groupService;
    private final PasskeyAuthService passkeyAuthService; // To get current user context

    @Autowired
    public GroupController(GroupService groupService, PasskeyAuthService passkeyAuthService) {
        this.groupService = groupService;
        this.passkeyAuthService = passkeyAuthService;
    }

    /**
     * Creates a new group.
     * @param createRequest DTO containing group name and initial member IDs.
     * @return The created group.
     */
    @PostMapping
    public ResponseEntity<Group> createGroup(@RequestBody CreateGroupRequest createRequest) {
        String creatorUserId = passkeyAuthService.getLocalUserId();
        if (creatorUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("POST /api/groups - createGroup called by user: {} with name: {}", creatorUserId, createRequest.getGroupName());
        try {
            Group createdGroup = groupService.createGroup(
                    createRequest.getGroupName(),
                    creatorUserId,
                    createRequest.getMemberIds()
            );
            return ResponseEntity.status(HttpStatus.CREATED).body(createdGroup);
        } catch (IllegalArgumentException e) {
            logger.error("Error creating group: {}", e.getMessage());
            return ResponseEntity.badRequest().build(); // Or a DTO with error info
        } catch (Exception e) {
            logger.error("Unexpected error creating group", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Gets a group by its ID.
     * @param groupId The ID of the group.
     * @return The group.
     */
    @GetMapping("/{groupId}")
    public ResponseEntity<Group> getGroupById(@PathVariable String groupId) {
        String currentUserId = passkeyAuthService.getLocalUserId();
        // TODO: Add permission check: ensure current user is a member of this group or it's public
        logger.info("GET /api/groups/{} - getGroupById called by user: {}", groupId, currentUserId);
        Optional<Group> group = groupService.findGroupById(groupId);
        return group.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Retrieves groups for the current user.
     * @param limit Max number of groups.
     * @param offset Offset for pagination.
     * @return List of groups.
     */
    @GetMapping
    public ResponseEntity<List<Group>> getMyGroups(
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "0") int offset) {
        String userId = passkeyAuthService.getLocalUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("GET /api/groups - getMyGroups called for user: {}", userId);
        List<Group> groups = groupService.getGroupsForUser(userId, limit, offset);
        return ResponseEntity.ok(groups);
    }

    /**
     * Adds a member to a group.
     * @param groupId The ID of the group.
     * @param memberRequest DTO containing the userId of the member to add.
     * @return ResponseEntity indicating success or failure.
     */
    @PostMapping("/{groupId}/members")
    public ResponseEntity<Void> addMemberToGroup(@PathVariable String groupId, @RequestBody MemberRequest memberRequest) {
        String currentUserId = passkeyAuthService.getLocalUserId();
        if (currentUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("POST /api/groups/{}/members - addMemberToGroup called by user: {} to add user: {}",
                groupId, currentUserId, memberRequest.getUserId());
        try {
            boolean success = groupService.addMemberToGroup(groupId, memberRequest.getUserId(), currentUserId);
            return success ? ResponseEntity.ok().build() : ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); // Or more specific error
        } catch (Exception e) {
            logger.error("Error adding member to group {}: {}", groupId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Removes a member from a group.
     * @param groupId The ID of the group.
     * @param memberId The ID of the member to remove.
     * @return ResponseEntity indicating success or failure.
     */
    @DeleteMapping("/{groupId}/members/{memberId}")
    public ResponseEntity<Void> removeMemberFromGroup(@PathVariable String groupId, @PathVariable String memberId) {
        String currentUserId = passkeyAuthService.getLocalUserId();
        if (currentUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("DELETE /api/groups/{}/members/{} - removeMemberFromGroup called by user: {}",
                groupId, memberId, currentUserId);
        try {
            boolean success = groupService.removeMemberFromGroup(groupId, memberId, currentUserId);
            return success ? ResponseEntity.noContent().build() : ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception e) {
            logger.error("Error removing member {} from group {}: {}", memberId, groupId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // DTOs for requests
    public static class CreateGroupRequest {
        private String groupName;
        private List<String> memberIds;
        // Getters and setters
        public String getGroupName() { return groupName; }
        public void setGroupName(String groupName) { this.groupName = groupName; }
        public List<String> getMemberIds() { return memberIds; }
        public void setMemberIds(List<String> memberIds) { this.memberIds = memberIds; }
    }

    public static class MemberRequest {
        private String userId;
        // Getter and setter
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
    }

    // TODO: Add endpoint for deleting a group (DELETE /{groupId})
    // TODO: Add endpoint for updating group details (PUT or PATCH /{groupId})
    // TODO: Add endpoint for listing group members (GET /{groupId}/members)
}

