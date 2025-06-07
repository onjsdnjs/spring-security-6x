package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.GroupRepository;
import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.service.UserManagementService;
import io.springsecurity.springsecurity6x.domain.dto.UserDto;
import io.springsecurity.springsecurity6x.entity.*;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service("userManagementService")
@RequiredArgsConstructor
public class UserManagementServiceImpl implements UserManagementService {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;

    // ... (modifyUser, getUser 메서드는 기존과 동일)
    @Transactional
    @Override
    @CacheEvict(value = "usersWithAuthorities", key = "#userDto.username", allEntries = true)
    public void modifyUser(@ModelAttribute UserDto userDto){
        Users users = userRepository.findById(userDto.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userDto.getId()));

        users.setName(userDto.getUsername());

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            users.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }
        users.getUserGroups().clear();

        if (userDto.getSelectedGroupIds() != null && !userDto.getSelectedGroupIds().isEmpty()) {
            Set<UserGroup> newUserGroups = new HashSet<>();
            for (Long groupId : userDto.getSelectedGroupIds()) {
                Group group = groupRepository.findById(groupId)
                        .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + groupId));
                newUserGroups.add(UserGroup.builder().user(users).group(group).build());
            }
            users.setUserGroups(newUserGroups);
        }
        userRepository.save(users);
        log.info("User {} (ID: {}) modified successfully.", users.getUsername(), users.getId());
    }

    @Transactional(readOnly = true)
    public UserDto getUser(Long id) {
        Users users = userRepository.findByIdWithGroupsRolesAndPermissions(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + id));
        UserDto userDto = modelMapper.map(users, UserDto.class);
        List<String> roles = users.getUserGroups().stream()
                .map(UserGroup::getGroup)
                .filter(java.util.Objects::nonNull)
                .flatMap(group -> group.getGroupRoles().stream())
                .map(GroupRole::getRole)
                .filter(java.util.Objects::nonNull)
                .map(Role::getRoleName)
                .distinct()
                .collect(Collectors.toList());

        List<String> permissions = users.getUserGroups().stream()
                .map(UserGroup::getGroup)
                .filter(java.util.Objects::nonNull)
                .flatMap(group -> group.getGroupRoles().stream())
                .map(GroupRole::getRole)
                .filter(java.util.Objects::nonNull)
                .flatMap(role -> role.getRolePermissions().stream())
                .map(RolePermission::getPermission)
                .filter(java.util.Objects::nonNull)
                .map(Permission::getName)
                .distinct()
                .collect(Collectors.toList());

        userDto.setRoles(roles);
        userDto.setPermissions(permissions);
        if (users.getUserGroups() != null) {
            userDto.setSelectedGroupIds(users.getUserGroups().stream()
                    .map(ug -> ug.getGroup().getId())
                    .collect(Collectors.toList()));
        } else {
            userDto.setSelectedGroupIds(List.of());
        }

        log.debug("Fetched user {} with roles: {} and permissions: {}", users.getUsername(), roles, permissions);
        return userDto;
    }


    @Transactional(readOnly = true)
    public List<Users> getUsers() {
        return userRepository.findAllWithDetails();
    }

    @Override
    @Transactional
    @CacheEvict(value = "usersWithAuthorities", key = "#id")
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
        log.info("User ID {} deleted.", id);
    }
}