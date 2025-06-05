package io.springsecurity.springsecurity6x.admin.service;

import io.springsecurity.springsecurity6x.entity.Group;

import java.util.List;
import java.util.Optional;

public interface GroupService {
    Group createGroup(Group group, List<Long> selectedRoleIds);
    Optional<Group> getGroup(Long id);
    List<Group> getAllGroups();
    void deleteGroup(Long id);
    Group updateGroup(Group group, List<Long> selectedRoleIds);
}
