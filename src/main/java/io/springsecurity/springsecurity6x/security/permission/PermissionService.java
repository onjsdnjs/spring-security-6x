package io.springsecurity.springsecurity6x.security.permission;

import io.springsecurity.springsecurity6x.entity.Permission;
import io.springsecurity.springsecurity6x.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict; // CacheEvict import
import org.springframework.cache.annotation.CachePut; // CachePut import
import org.springframework.cache.annotation.Cacheable; // Cacheable import
import org.springframework.cache.annotation.Caching; // Caching import
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true) // 기본적으로 읽기 전용 트랜잭션 적용
public class PermissionService {
    private final PermissionRepository permissionRepository;

    /**
     * 새로운 Permission을 생성하고 저장합니다.
     * 관련 캐시(usersWithRolesAndPermissions)를 무효화하여 최신 권한 정보를 반영합니다.
     * @param permission 생성할 Permission 엔티티
     * @return 생성된 Permission 엔티티
     */
    @Transactional // 쓰기 작업이므로 명시적 트랜잭션 필요
    @Caching(
            evict = { @CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true) }, // 모든 사용자 권한 캐시 무효화
            put = { @CachePut(value = "permissions", key = "#result.id") } // 특정 Permission 캐시 (선택적)
    )
    public Permission createPermission(Permission permission) {
        // 중복 이름 체크 로직 추가 권장 (Unique Constraint로 DB에서 잡히겠지만, 서비스 계층에서 명확히)
        if (permissionRepository.findByName(permission.getName()).isPresent()) {
            throw new IllegalArgumentException("Permission with name " + permission.getName() + " already exists.");
        }
        return permissionRepository.save(permission);
    }

    /**
     * ID로 Permission 엔티티를 조회합니다.
     * @param id 조회할 Permission ID
     * @return 해당 Permission 엔티티 (Optional)
     */
    @Cacheable(value = "permissions", key = "#id") // ID로 조회 시 캐싱
    public Optional<Permission> getPermission(Long id) {
        return permissionRepository.findById(id);
    }

    /**
     * 모든 Permission 엔티티를 조회합니다.
     * @return 모든 Permission 엔티티 리스트
     */
    @Cacheable(value = "permissions", key = "'allPermissions'") // 모든 권한 목록 캐싱
    public List<Permission> getAllPermissions() {
        return permissionRepository.findAll();
    }

    /**
     * ID로 Permission 엔티티를 삭제합니다.
     * 관련 캐시(usersWithRolesAndPermissions, 모든 Permission 캐시)를 무효화합니다.
     * @param id 삭제할 Permission ID
     */
    @Transactional // 쓰기 작업이므로 명시적 트랜잭션 필요
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true), // 모든 사용자 권한 캐시 무효화
                    @CacheEvict(value = "permissions", key = "#id"), // 특정 Permission 캐시 무효화
                    @CacheEvict(value = "permissions", key = "'allPermissions'") // 전체 Permission 목록 캐시 무효화
            }
    )
    public void deletePermission(Long id) {
        permissionRepository.deleteById(id);
    }

    /**
     * Permission 엔티티를 업데이트합니다.
     * 관련 캐시(usersWithRolesAndPermissions, 특정 Permission 캐시)를 갱신합니다.
     * @param permission 업데이트할 Permission 엔티티 (ID 포함)
     * @return 업데이트된 Permission 엔티티
     */
    @Transactional // 쓰기 작업이므로 명시적 트랜잭션 필요
    @Caching(
            evict = { @CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true) }, // 모든 사용자 권한 캐시 무효화
            put = { @CachePut(value = "permissions", key = "#result.id") } // 특정 Permission 캐시 갱신
    )
    public Permission updatePermission(Permission permission) {
        // ID 존재 여부 확인 로직 (선택적)
        // if (!permissionRepository.existsById(permission.getId())) {
        //     throw new IllegalArgumentException("Permission with ID " + permission.getId() + " not found for update.");
        // }
        return permissionRepository.save(permission);
    }

    /**
     * 권한 이름(name)으로 Permission 엔티티를 조회합니다.
     * @param name 조회할 권한 이름
     * @return 해당 Permission 엔티티 (Optional)
     */
    @Cacheable(value = "permissionsByName", key = "#name") // 이름으로 조회 시 캐싱
    public Optional<Permission> findByName(String name) {
        return permissionRepository.findByName(name);
    }
}