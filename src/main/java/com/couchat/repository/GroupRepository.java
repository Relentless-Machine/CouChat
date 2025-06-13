package com.couchat.repository;

import com.couchat.group.model.Group;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for {@link Group} entities.
 * Defines a contract for data access operations related to groups and their members.
 */
public interface GroupRepository {

    /**
     * Saves a new group or updates an existing one in the database.
     *
     * @param group The {@link Group} object to save. Must not be null.
     * @return The saved {@link Group} object.
     */
    Group save(Group group);

    /**
     * Finds a group by its unique ID.
     *
     * @param groupId The ID of the group to find. Must not be null.
     * @return An {@link Optional} containing the {@link Group} if found, or an empty Optional otherwise.
     */
    Optional<Group> findById(String groupId);

    /**
     * Finds groups whose names contain the given string (case-insensitive).
     *
     * @param nameSubstring The substring to search for in group names. Must not be null.
     * @return A list of {@link Group} objects matching the criteria.
     */
    List<Group> findByGroupNameContainingIgnoreCase(String nameSubstring);

    /**
     * Retrieves all groups a specific user is a member of.
     *
     * @param userId The ID of the user. Must not be null.
     * @param limit The maximum number of groups to retrieve.
     * @param offset The starting point for retrieving groups (for pagination).
     * @return A list of {@link Group} objects the user is a member of.
     */
    List<Group> findAllByMemberUserId(String userId, int limit, int offset);

    /**
     * Deletes a group by its unique ID.
     * This should also handle the deletion of group memberships due to ON DELETE CASCADE.
     *
     * @param groupId The ID of the group to delete. Must not be null.
     * @return true if the group was deleted successfully, false otherwise.
     */
    boolean deleteById(String groupId);

    // Group Member Management

    /**
     * Adds a user to a group.
     *
     * @param groupId The ID of the group. Must not be null.
     * @param userId The ID of the user to add. Must not be null.
     * @param role The role of the user in the group (e.g., "MEMBER", "ADMIN"). Must not be null.
     * @return true if the user was added successfully, false if the user is already a member or an error occurred.
     */
    boolean addMember(String groupId, String userId, String role);

    /**
     * Removes a user from a group.
     *
     * @param groupId The ID of the group. Must not be null.
     * @param userId The ID of the user to remove. Must not be null.
     * @return true if the user was removed successfully, false otherwise.
     */
    boolean removeMember(String groupId, String userId);

    /**
     * Retrieves all member IDs for a given group.
     *
     * @param groupId The ID of the group. Must not be null.
     * @return A list of user IDs who are members of the group.
     */
    List<String> findMemberIdsByGroupId(String groupId);

    /**
     * Updates the role of a member in a group.
     *
     * @param groupId The ID of the group. Must not be null.
     * @param userId The ID of the user whose role is to be updated. Must not be null.
     * @param newRole The new role for the user. Must not be null.
     * @return true if the role was updated successfully, false otherwise.
     */
    boolean updateMemberRole(String groupId, String userId, String newRole);

    /**
     * Checks if a user is a member of a specific group.
     *
     * @param groupId The ID of the group. Must not be null.
     * @param userId The ID of the user. Must not be null.
     * @return true if the user is a member, false otherwise.
     */
    boolean isUserMemberOfGroup(String groupId, String userId);
}

