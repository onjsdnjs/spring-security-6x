package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.GroupRepository;
import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.service.GroupService;
import io.springsecurity.springsecurity6x.entity.Group;
import io.springsecurity.springsecurity6x.entity.GroupRole;
import io.springsecurity.springsecurity6x.entity.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class GroupServiceImpl implements GroupService {
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository; // RoleRepository 주입

    /**
     * 새로운 Group을 생성하고 저장합니다. Role 할당 로직 포함.
     * `GroupRole` 조인 엔티티를 통해 `Role`과의 관계를 설정합니다.
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true), // 사용자 권한 캐시 무효화
                    @CacheEvict(value = "groups", allEntries = true) // 모든 그룹 캐시 무효화
            },
            put = { @CachePut(value = "groups", key = "#result.id") } // 특정 그룹 캐시 갱신
    )
    public Group createGroup(Group group, List<Long> selectedRoleIds) {
        if (groupRepository.findByName(group.getName()).isPresent()) {
            throw new IllegalArgumentException("Group with name " + group.getName() + " already exists.");
        }

        Group savedGroup = groupRepository.save(group);

        // GroupRole 조인 엔티티 생성 및 연결
        if (selectedRoleIds != null && !selectedRoleIds.isEmpty()) {
            Set<GroupRole> groupRoles = new HashSet<>();
            for (Long roleId : selectedRoleIds) {
                Role role = roleRepository.findById(roleId)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + roleId));
                groupRoles.add(GroupRole.builder().group(savedGroup).role(role).build());
            }
            savedGroup.setGroupRoles(groupRoles); // Group 엔티티에 조인 엔티티 설정
        }

        return groupRepository.save(savedGroup); // 다시 저장하여 관계 반영
    }

    public Optional<Group> getGroup(Long id) {
        // Group 엔티티 로드 시 groupRoles 및 role 엔티티를 함께 fetch join
        // GroupRepository에 findByIdWithRoles 쿼리 추가 필요
        return groupRepository.findByIdWithRoles(id);
    }

    @Cacheable(value = "groups", key = "'allGroups'")
    public List<Group> getAllGroups() {
        // Group 엔티티 로드 시 groupRoles 및 role 엔티티를 함께 fetch join
        // GroupRepository에 findAllWithRoles 쿼리 추가 필요
        return groupRepository.findAllWithRoles();
    }

    /**
     * Group을 삭제합니다.
     * 관련 캐시를 무효화합니다.
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "groups", allEntries = true),
                    @CacheEvict(value = "groups", key = "#id")
            }
    )
    public void deleteGroup(Long id) {
        groupRepository.deleteById(id);
    }

    /**
     * 기존 Group을 업데이트하고 저장합니다. Role 할당 로직 포함.
     * `GroupRole` 조인 엔티티를 통해 `Role`과의 관계를 업데이트합니다.
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "groups", allEntries = true)
            },
            put = { @CachePut(value = "groups", key = "#result.id") }
    )
    public Group updateGroup(Group group, List<Long> selectedRoleIds) {
        Group existingGroup = groupRepository.findByIdWithRoles(group.getId())
                .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + group.getId()));

        existingGroup.setName(group.getName());
        existingGroup.setDescription(group.getDescription());

        // 기존 GroupRole 관계 제거 (orphanRemoval = true 덕분에 가능)
        existingGroup.getGroupRoles().clear();

        // 새로운 GroupRole 조인 엔티티 생성 및 연결
        if (selectedRoleIds != null && !selectedRoleIds.isEmpty()) {
            for (Long roleId : selectedRoleIds) {
                Role role = roleRepository.findById(roleId)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + roleId));
                existingGroup.getGroupRoles().add(GroupRole.builder().group(existingGroup).role(role).build());
            }
        }

        return groupRepository.save(existingGroup);
    }
}
