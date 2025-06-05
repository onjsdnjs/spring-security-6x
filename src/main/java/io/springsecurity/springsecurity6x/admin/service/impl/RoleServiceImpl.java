package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.PermissionRepository;
import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.entity.Permission;
import io.springsecurity.springsecurity6x.entity.Role;
import io.springsecurity.springsecurity6x.entity.RolePermission;
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
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Transactional(readOnly = true)
    @Cacheable(value = "roles", key = "#id")
    public Role getRole(long id) {
        // findByIdWithPermissions는 RoleRepository에 정의되어 있습니다.
        return roleRepository.findByIdWithPermissions(id)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + id));
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "roles", key = "'allRoles'")
    public List<Role> getRoles() {
        return roleRepository.findAll();
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "rolesWithoutExpression", key = "'allRolesWithoutExpression'")
    public List<Role> getRolesWithoutExpression() {
        return roleRepository.findAllRolesWithoutExpression();
    }

    /**
     * 새로운 Role을 생성하고 저장합니다. Permission 할당 로직 포함.
     * `RolePermission` 조인 엔티티를 통해 `Permission`과의 관계를 설정합니다.
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true), // usersWithRolesAndPermissions -> usersWithAuthorities
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = {@CachePut(value = "roles", key = "#result.id")}
    )
    public Role createRole(Role role, List<Long> permissionIds) {
        if (roleRepository.findByRoleName(role.getRoleName()).isPresent()) {
            throw new IllegalArgumentException("Role with name " + role.getRoleName() + " already exists.");
        }

        // 먼저 Role을 저장하여 ID를 얻습니다. (detached 상태가 되지 않도록)
        Role savedRole = roleRepository.save(role);

        // RolePermission 조인 엔티티 생성 및 연결
        Set<RolePermission> rolePermissions = new HashSet<>();
        if (permissionIds != null && !permissionIds.isEmpty()) {
            for (Long permId : permissionIds) {
                Permission permission = permissionRepository.findById(permId)
                        .orElseThrow(() -> new IllegalArgumentException("Permission not found with ID: " + permId));
                rolePermissions.add(RolePermission.builder().role(savedRole).permission(permission).build());
            }
        }
        savedRole.setRolePermissions(rolePermissions); // Role 엔티티에 조인 엔티티 설정

        return roleRepository.save(savedRole); // 다시 저장하여 관계 반영
    }

    /**
     * 기존 Role을 업데이트하고 저장합니다. Permission 할당 로직 포함.
     * `RolePermission` 조인 엔티티를 통해 `Permission`과의 관계를 업데이트합니다.
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = {@CachePut(value = "roles", key = "#result.id")}
    )
    public Role updateRole(Role role, List<Long> permissionIds) {
        // Fetch Join을 통해 기존 Role과 RolePermission 관계를 함께 가져옵니다.
        Role existingRole = roleRepository.findByIdWithPermissions(role.getId())
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + role.getId()));

        existingRole.setRoleName(role.getRoleName());
        existingRole.setRoleDesc(role.getRoleDesc());
        existingRole.setIsExpression(role.getIsExpression());

        // 기존 RolePermission 관계 제거 (orphanRemoval = true 덕분에 가능)
        existingRole.getRolePermissions().clear();

        // 새로운 RolePermission 조인 엔티티 생성 및 연결
        if (permissionIds != null && !permissionIds.isEmpty()) {
            for (Long permId : permissionIds) {
                Permission permission = permissionRepository.findById(permId)
                        .orElseThrow(() -> new IllegalArgumentException("Permission not found with ID: " + permId));
                existingRole.getRolePermissions().add(RolePermission.builder().role(existingRole).permission(permission).build());
            }
        }
        // Save는 자동으로 변경을 감지하여 처리
        return roleRepository.save(existingRole);
    }


    /**
     * Role을 삭제합니다.
     * 관련 캐시를 무효화합니다.
     * @param id 삭제할 Role ID
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true),
                    @CacheEvict(value = "roles", key = "#id")
            }
    )
    public void deleteRole(long id) {
        roleRepository.deleteById(id);
    }
}
