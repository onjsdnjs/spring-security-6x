package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.RoleHierarchyRepository;
import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.entity.RoleHierarchyEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class RoleHierarchyService {

    private final RoleHierarchyRepository roleHierarchyRepository;
    private final RoleRepository roleRepository; // 역할 이름의 유효성을 검증하기 위함
    private final RoleHierarchyImpl applicationRoleHierarchy; // PlatformSecurityConfig에서 정의된 RoleHierarchyImpl 빈 주입

    /**
     * 모든 역할 계층 설정을 조회합니다.
     */
    @Cacheable(value = "roleHierarchies", key = "'allRoleHierarchies'")
    public List<RoleHierarchyEntity> getAllRoleHierarchies() {
        return roleHierarchyRepository.findAll();
    }

    /**
     * ID로 역할 계층 설정을 조회합니다.
     */
    @Cacheable(value = "roleHierarchies", key = "#id")
    public Optional<RoleHierarchyEntity> getRoleHierarchy(Long id) {
        return roleHierarchyRepository.findById(id);
    }

    /**
     * 현재 활성화된 역할 계층 문자열을 DB에서 로드합니다.
     * 캐싱을 통해 불필요한 DB 조회를 줄입니다.
     */
    @Cacheable(value = "activeRoleHierarchyString", key = "'current'")
    public String getActiveRoleHierarchyString() {
        return roleHierarchyRepository.findByIsActiveTrue()
                .map(RoleHierarchyEntity::getHierarchyString)
                .orElse(""); // 활성화된 것이 없으면 빈 문자열 반환
    }

    /**
     * 새로운 역할 계층 설정을 생성합니다.
     * @param roleHierarchyEntity 생성할 엔티티
     * @return 생성된 엔티티
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true), // 사용자 권한 캐시 무효화 (계층 변경 시 재로딩 필요)
                    @CacheEvict(value = "roleHierarchies", allEntries = true), // 모든 계층 캐시 무효화
                    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true) // 활성 계층 문자열 캐시 무효화
            },
            put = { @CachePut(value = "roleHierarchies", key = "#result.id") }
    )
    public RoleHierarchyEntity createRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        // 중복 계층 문자열 체크
        if (roleHierarchyRepository.findByHierarchyString(roleHierarchyEntity.getHierarchyString()).isPresent()) {
            throw new IllegalArgumentException("Role hierarchy string already exists.");
        }
        // 계층 문자열 유효성 검증 (참조하는 역할 이름이 DB에 존재하는지)
        validateHierarchyString(roleHierarchyEntity.getHierarchyString());

        RoleHierarchyEntity savedEntity = roleHierarchyRepository.save(roleHierarchyEntity);

        // 만약 새로 생성하는 것을 활성화한다면, 기존 활성화를 비활성화하고 이 엔티티를 활성화
        if (savedEntity.getIsActive()) {
            deactivateAllOtherHierarchies(savedEntity.getId());
            reloadRoleHierarchyBean(); // 런타임에 RoleHierarchyImpl 빈 갱신
        }
        log.info("Created RoleHierarchyEntity with ID: {}", savedEntity.getId());
        return savedEntity;
    }

    /**
     * 기존 역할 계층 설정을 업데이트합니다.
     * @param roleHierarchyEntity 업데이트할 엔티티 (ID 포함)
     * @return 업데이트된 엔티티
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roleHierarchies", allEntries = true),
                    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true)
            },
            put = { @CachePut(value = "roleHierarchies", key = "#result.id") }
    )
    public RoleHierarchyEntity updateRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        RoleHierarchyEntity existingEntity = roleHierarchyRepository.findById(roleHierarchyEntity.getId())
                .orElseThrow(() -> new IllegalArgumentException("RoleHierarchy not found with ID: " + roleHierarchyEntity.getId()));

        // 계층 문자열 유효성 검증
        validateHierarchyString(roleHierarchyEntity.getHierarchyString());

        existingEntity.setHierarchyString(roleHierarchyEntity.getHierarchyString());
        existingEntity.setDescription(roleHierarchyEntity.getDescription());
        existingEntity.setIsActive(roleHierarchyEntity.getIsActive());

        RoleHierarchyEntity updatedEntity = roleHierarchyRepository.save(existingEntity);

        if (updatedEntity.getIsActive()) {
            deactivateAllOtherHierarchies(updatedEntity.getId());
        }
        reloadRoleHierarchyBean(); // 런타임에 RoleHierarchyImpl 빈 갱신
        log.info("Updated RoleHierarchyEntity with ID: {}", updatedEntity.getId());
        return updatedEntity;
    }

    /**
     * 특정 역할 계층 설정을 삭제합니다.
     * @param id 삭제할 엔티티 ID
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roleHierarchies", allEntries = true),
                    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true),
                    @CacheEvict(value = "roleHierarchies", key = "#id")
            }
    )
    public void deleteRoleHierarchy(Long id) {
        roleHierarchyRepository.deleteById(id);
        reloadRoleHierarchyBean(); // 런타임에 RoleHierarchyImpl 빈 갱신
        log.info("Deleted RoleHierarchyEntity with ID: {}", id);
    }

    /**
     * 특정 RoleHierarchyEntity를 활성화하고, 나머지 모든 계층 설정을 비활성화합니다.
     * @param activeId 활성화할 RoleHierarchyEntity의 ID
     */
    @Transactional
    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true) // 활성 계층 문자열 캐시 무효화
    public void activateRoleHierarchy(Long activeId) {
        List<RoleHierarchyEntity> all = roleHierarchyRepository.findAll();
        for (RoleHierarchyEntity entity : all) {
            entity.setIsActive(Objects.equals(entity.getId(), activeId));
            roleHierarchyRepository.save(entity);
        }
        reloadRoleHierarchyBean(); // 런타임에 RoleHierarchyImpl 빈 갱신
        log.info("Activated RoleHierarchyEntity with ID: {}", activeId);
    }


    /**
     * RoleHierarchyImpl 빈에 DB에서 로드한 최신 계층 문자열을 설정합니다.
     * 이 메서드는 PlatformSecurityConfig에서 @Bean 초기화 시 호출됩니다.
     * 또한, DB에서 계층 정보가 변경될 때마다 수동으로 호출되어 런타임 갱신을 수행합니다.
     */
    public void reloadRoleHierarchyBean() {
        try {
            String hierarchyString = getActiveRoleHierarchyString(); // DB에서 활성화된 계층 문자열 로드 (캐시 사용)
            applicationRoleHierarchy.setHierarchy(hierarchyString); // RoleHierarchyImpl 빈에 설정
            log.info("RoleHierarchyImpl bean reloaded with new hierarchy: \n{}", hierarchyString);
        } catch (Exception e) {
            log.error("Failed to reload RoleHierarchyImpl bean dynamically. Error: {}", e.getMessage(), e);
        }
    }

    /**
     * 계층 문자열에 포함된 역할 이름들이 DB에 실제로 존재하는 역할들인지 검증합니다.
     * @param hierarchyString 검증할 계층 문자열 (예: "ROLE_A > ROLE_B\nROLE_C > ROLE_D")
     * @throws IllegalArgumentException 유효하지 않은 역할 이름이 포함될 경우
     */
    private void validateHierarchyString(String hierarchyString) {
        if (hierarchyString == null || hierarchyString.trim().isEmpty()) {
            return; // 빈 문자열은 유효
        }
        // 계층 문자열을 파싱하여 역할 이름만 추출
        Set<String> referencedRoleNames = Arrays.stream(hierarchyString.split("[\\n>]")) // 개행문자나 '>'로 분리
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());

        // 'ROLE_' 접두사 제거 (DB의 roleName은 접두사 없음)
        Set<String> cleanRoleNames = referencedRoleNames.stream()
                .map(s -> s.startsWith("ROLE_") ? s.substring(5) : s)
                .collect(Collectors.toSet());

        // DB에 존재하는 모든 역할 이름 조회
        Set<String> existingRoleNames = roleRepository.findAll().stream()
                .map(role -> role.getRoleName().toUpperCase()) // DB 역할 이름은 대문자로 가정
                .collect(Collectors.toSet());

        // 계층 문자열에 참조된 역할 이름 중 DB에 존재하지 않는 것이 있는지 확인
        for (String roleName : cleanRoleNames) {
            if (!existingRoleNames.contains(roleName.toUpperCase())) {
                throw new IllegalArgumentException("Hierarchy string contains invalid role name: " + roleName + ". Role does not exist in the database.");
            }
        }
    }

    // 다른 활성 계층 설정을 비활성화하는 헬퍼 메서드
    private void deactivateAllOtherHierarchies(Long currentActiveId) {
        roleHierarchyRepository.findByIsActiveTrue()
                .filter(e -> !e.getId().equals(currentActiveId))
                .ifPresent(e -> {
                    e.setIsActive(false);
                    roleHierarchyRepository.save(e);
                });
    }
}