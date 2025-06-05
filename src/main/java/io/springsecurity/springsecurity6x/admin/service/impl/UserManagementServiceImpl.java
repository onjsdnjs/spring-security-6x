package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.repository.UserManagementRepository;
import io.springsecurity.springsecurity6x.admin.service.UserManagementService;
import io.springsecurity.springsecurity6x.domain.dto.AccountDto;
import io.springsecurity.springsecurity6x.domain.dto.UserDto;
import io.springsecurity.springsecurity6x.entity.Role;
import io.springsecurity.springsecurity6x.entity.UserGroup;
import io.springsecurity.springsecurity6x.entity.Users;
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
    @CacheEvict(value = "usersWithAuthorities", key = "#accountDto.username") // 사용자 권한 캐시 무효화 (username 기준)
    public void modifyUser(UserDto userDto){ // AccountDto 대신 UserDto
        // UserDto를 Users 엔티티로 매핑
        Users users = userRepository.findById(userDto.getId()) // ID로 Users 엔티티를 로드
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userDto.getId()));

        users.setPassword(passwordEncoder.encode(userDto.getPassword())); // 비밀번호는 항상 업데이트
        users.setName(userDto.getUsername()); // 이름 업데이트

        // **새로운 그룹 관계 업데이트 로직 (userDto에 selectedGroupIds 필드가 있다고 가정)**
        // 현재는 DTO에 `roles` (List<String>)만 있다고 가정하고, 이를 Group으로 변환하는 로직을 임시로 넣습니다.
        // 하지만 궁극적으로 UserDto에는 `List<Long> selectedGroupIds`가 있어야 합니다.
        // 임시 방안: UserDto의 `roles` 필드를 `UserGroup`으로 매핑하는 로직이 없으므로,
        // 이 메서드는 User의 비밀번호와 이름만 업데이트하고, 그룹/역할 할당은 `GroupController`나 `RoleController`에서 처리한다고 가정합니다.
        // 아니면, `UserDto`에 `List<Long> selectedGroupIds` 필드를 추가하고,
        // `GroupRepository`를 통해 Group 엔티티를 조회하여 `UserGroup` 관계를 업데이트해야 합니다.

        // **현재 DTO 구조에 맞춰서, 기존 String roles 필드를 업데이트하거나,
        //   새로운 Group-Role 관계가 DTO를 통해 들어온다고 가정하고 업데이트 로직을 추가해야 합니다.**
        // **여기서는 Users 엔티티의 `roles` (String) 필드를 업데이트하는 것으로 임시 처리합니다.**
        users.setRoles(String.join(",", userDto.getRoles())); // UserDto의 getRoles()는 List<String> 반환 가정

        // users.setUserGroups(...) // 이 부분은 Group 관리 기능 구현 후 DTO에 맞춰 구현 예정

        userRepository.save(users);
        log.info("User {} modified.", users.getUsername());
    }

    @Transactional(readOnly = true)
    public UserDto getUser(Long id) { // AccountDto 대신 UserDto
        Users users = userRepository.findById(id).orElse(new Users()); // Account 대신 Users
        ModelMapper modelMapper = new ModelMapper();
        UserDto userDto = modelMapper.map(users, UserDto.class); // AccountDto 대신 UserDto

        // 그룹 관계에서 역할 목록 추출 (새로운 관계에 맞춰 변경)
        // users.getUserGroups() -> Group -> GroupRole -> Role 로 변경
        List<String> roles = users.getUserGroups().stream() // users.getUserGroups() 사용
                .flatMap(ug -> Optional.ofNullable(ug.getGroup()).stream()) // UserGroup에서 Group 가져오기
                .flatMap(group -> Optional.ofNullable(group.getGroupRoles()).stream()) // Group에서 GroupRole 가져오기
                .flatMap(gr -> Optional.ofNullable(gr.getRole()).stream()) // GroupRole에서 Role 가져오기
                .map(Role::getRoleName) // Role에서 roleName 가져오기
                .distinct() // 중복 역할 이름 제거
                .collect(Collectors.toList());

        userDto.setRoles(roles);
        log.debug("Fetched user {} with roles: {}", users.getUsername(), roles);
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