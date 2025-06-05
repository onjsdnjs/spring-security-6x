package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.entity.Permission;
import io.springsecurity.springsecurity6x.entity.Role;
import io.springsecurity.springsecurity6x.admin.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository; // PermissionRepository 주입

    @Transactional(readOnly = true)
    @Cacheable(value = "roles", key = "#id") // 특정 ID로 Role 조회 시 캐싱
    public Role getRole(long id) {
        // findByIdWithPermissions는 RoleRepository에 정의되어 있습니다.
        return roleRepository.findByIdWithPermissions(id)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + id));
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "roles", key = "'allRoles'") // 모든 역할 목록 캐싱, key는 문자열 리터럴
    public List<Role> getRoles() {
        return roleRepository.findAll();
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "rolesWithoutExpression", key = "'allRolesWithoutExpression'") // 표현식 없는 역할 목록 캐싱, key는 문자열 리터럴
    public List<Role> getRolesWithoutExpression() {
        return roleRepository.findAllRolesWithoutExpression();
    }

    /**
     * 새로운 Role을 생성하고 저장합니다. Permission 할당 로직 포함.
     * 관련 캐시(usersWithRolesAndPermissions, roles, rolesWithoutExpression)를 무효화합니다.
     * @param role 저장할 Role 엔티티
     * @param permissionIds 할당할 Permission ID 목록
     */
    @Transactional // 쓰기 작업
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true), // 모든 사용자 권한 캐시 무효화
                    @CacheEvict(value = "roles", allEntries = true), // 모든 역할 캐시 무효화
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true) // 표현식 없는 역할 캐시 무효화
            },
            put = { @CachePut(value = "roles", key = "#result.id") } // 생성된 Role을 ID로 캐싱 (결과 객체 사용)
    )
    public Role createRole(Role role, List<Long> permissionIds) {
        // 중복 roleName 체크 로직 추가 권장 (Unique Constraint로 DB에서 잡히겠지만)
        if (roleRepository.findByRoleName(role.getRoleName()).isPresent()) {
            throw new IllegalArgumentException("Role with name " + role.getRoleName() + " already exists.");
        }

        // Permission 엔티티 조회 및 할당
        Set<Permission> permissions = new HashSet<>();
        if (permissionIds != null && !permissionIds.isEmpty()) {
            permissions = permissionIds.stream()
                    .map(permissionRepository::findById)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .collect(Collectors.toSet());
        }
        role.setPermissions(permissions);

        return roleRepository.save(role);
    }

    /**
     * 기존 Role을 업데이트하고 저장합니다. Permission 할당 로직 포함.
     * 관련 캐시를 무효화합니다.
     * @param role 업데이트할 Role 엔티티 (ID 포함)
     * @param permissionIds 할당할 Permission ID 목록
     * @return 업데이트된 Role 엔티티
     */
    @Transactional // 쓰기 작업
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = { @CachePut(value = "roles", key = "#result.id") } // 업데이트된 Role을 ID로 캐싱
    )
    public Role updateRole(Role role, List<Long> permissionIds) {
        Role existingRole = roleRepository.findByIdWithPermissions(role.getId())
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + role.getId()));

        // 역할 이름, 설명, 표현식 여부 업데이트
        existingRole.setRoleName(role.getRoleName());
        existingRole.setRoleDesc(role.getRoleDesc());
        existingRole.setIsExpression(role.getIsExpression());

        // Permission 엔티티 조회 및 업데이트
        Set<Permission> permissions = new HashSet<>();
        if (permissionIds != null && !permissionIds.isEmpty()) {
            permissions = permissionIds.stream()
                    .map(permissionRepository::findById)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .collect(Collectors.toSet());
        }
        existingRole.setPermissions(permissions); // 기존 권한 목록을 새 목록으로 대체

        return roleRepository.save(existingRole);
    }


    /**
     * Role을 삭제합니다.
     * 관련 캐시를 무효화합니다.
     * @param id 삭제할 Role ID
     */
    @Transactional // 쓰기 작업
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true),
                    @CacheEvict(value = "roles", key = "#id") // 특정 Role ID 캐시 무효화
            }
    )
    public void deleteRole(long id) {
        roleRepository.deleteById(id);
    }
}
