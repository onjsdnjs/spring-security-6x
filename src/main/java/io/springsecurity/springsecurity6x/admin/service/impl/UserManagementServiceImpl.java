package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.repository.UserManagementRepository;
import io.springsecurity.springsecurity6x.admin.service.UserManagementService;
import io.springsecurity.springsecurity6x.domain.dto.AccountDto;
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

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service("userManagementService")
@RequiredArgsConstructor
public class UserManagementServiceImpl implements UserManagementService {

    private final UserRepository userRepository; // UserManagementRepository 대신 UserRepository 사용
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;

    // GroupRepository 주입 (그룹을 조회하여 UserGroup에 연결하기 위함)
    // private final GroupRepository groupRepository; // GroupRepository가 구현되었다면 주입

    @Transactional
    @Override
    @CacheEvict(value = "usersWithAuthorities", key = "#userDto.username", allEntries = true) // 사용자 권한 캐시 무효화 (username 기준)
    public void modifyUser(UserDto userDto){ // AccountDto 대신 UserDto 사용
        // 1. 기존 Users 엔티티 로드 (없으면 예외)
        Users users = userRepository.findById(userDto.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userDto.getId()));

        // 2. 기본 사용자 정보 업데이트 (username은 변경 불가 필드로 가정)
        users.setName(userDto.getUsername());
        // 비밀번호는 DTO에 포함되어 있다면 업데이트 (평문 -> 인코딩)
        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            users.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }
        // age 필드가 Users 엔티티에 추가되었다면 DTO에서 받아 업데이트
        // users.setAge(userDto.getAge()); // UserDto에 age 필드 추가 필요

        // 3. User-Group 관계 업데이트 (OneToMany - UserGroup 조인 엔티티 활용)
        // 기존 userGroups 관계를 모두 삭제하고 새로운 관계를 설정합니다. (orphanRemoval = true 시 동작)
        users.getUserGroups().clear(); // 기존 연결 끊기

        if (userDto.getSelectedGroupIds() != null && !userDto.getSelectedGroupIds().isEmpty()) { // UserDto에 selectedGroupIds 필드가 있다고 가정
            Set<UserGroup> newUserGroups = new HashSet<>();
            for (Long groupId : userDto.getSelectedGroupIds()) {
                Group group = groupRepository.findById(groupId)
                        .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + groupId));
                // UserGroup 엔티티 생성 및 Users, Group 연결
                newUserGroups.add(UserGroup.builder().user(users).group(group).build());
            }
            users.setUserGroups(newUserGroups); // Users 엔티티에 업데이트된 그룹 관계 설정
        }

        // 5. Users 엔티티 저장 (변경 감지 후 자동 업데이트)
        userRepository.save(users);
        log.info("User {} (ID: {}) modified successfully.", users.getUsername(), users.getId());
    }

    @Transactional(readOnly = true)
    public UserDto getUser(Long id) {
        Users users = userRepository.findByIdWithGroupsRolesAndPermissions(id) // Group, Role, Permission을 Fetch Join
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + id));

        // ModelMapper 사용 (필드명 매핑에 따라 DTO 필드명 조정 필요)
        UserDto userDto = modelMapper.map(users, UserDto.class);

        // User-Group-Role-Permission 관계에서 역할 및 권한 목록 추출
        List<String> roles = users.getUserGroups().stream() // UserGroup에서 시작
                .map(UserGroup::getGroup) // Group 가져오기
                .filter(java.util.Objects::nonNull)
                .flatMap(group -> group.getGroupRoles().stream()) // GroupRole 가져오기
                .map(GroupRole::getRole) // Role 가져오기
                .filter(java.util.Objects::nonNull)
                .map(Role::getRoleName) // Role 이름 추출
                .distinct() // 중복 제거 (한 사용자가 여러 그룹에 속하고, 그 그룹들이 같은 역할을 가질 수 있으므로)
                .collect(Collectors.toList());

        List<String> permissions = users.getUserGroups().stream()
                .map(UserGroup::getGroup)
                .filter(java.util.Objects::nonNull)
                .flatMap(group -> group.getGroupRoles().stream())
                .map(GroupRole::getRole)
                .filter(java.util.Objects::nonNull)
                .flatMap(role -> role.getRolePermissions().stream()) // RolePermission 가져오기
                .map(RolePermission::getPermission) // Permission 가져오기
                .filter(java.util.Objects::nonNull)
                .map(Permission::getName) // Permission 이름 추출
                .distinct() // 중복 제거
                .collect(Collectors.toList());

        userDto.setRoles(roles); // UserDto에 `List<String> roles` 필드가 있다고 가정
        userDto.setPermissions(permissions); // UserDto에 `List<String> permissions` 필드 추가 필요

        // UserDto에 `selectedGroupIds`를 채워서 UI에 그룹 선택 상태 표시
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
    public List<Users> getUsers() { // Account 대신 Users
        return userRepository.findAll();
    }

    @Override
    @Transactional // 쓰기 작업
    @CacheEvict(value = "usersWithAuthorities", key = "#id") // 사용자 권한 캐시 무효화 (ID 기준)
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
        log.info("User ID {} deleted.", id);
    }

}