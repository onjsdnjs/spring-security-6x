package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.RoleHierarchyRepository;
import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.entity.RoleHierarchyEntity;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
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
    private final RoleRepository roleRepository;
    private final RoleHierarchyImpl roleHierarchy;

    /**
     * RoleHierarchyService 빈 생성이 완료된 후, RoleHierarchyImpl 빈에 계층 정보를 설정합니다.
     */
    @PostConstruct // <<< 이 메서드를 추가합니다.
    public void initializeRoleHierarchy() {
        log.info("Initializing RoleHierarchyService and setting initial RoleHierarchyImpl hierarchy...");
        reloadRoleHierarchyBean();
    }

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
                .orElse("");
    }

    /**
     * 새로운 역할 계층 설정을 생성합니다.
     * (이전 응답에서 제공된 createRoleHierarchy 메서드 내용 그대로)
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
    public RoleHierarchyEntity createRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        if (roleHierarchyRepository.findByHierarchyString(roleHierarchyEntity.getHierarchyString()).isPresent()) {
            throw new IllegalArgumentException("Role hierarchy string already exists.");
        }
        validateHierarchyString(roleHierarchyEntity.getHierarchyString());

        RoleHierarchyEntity savedEntity = roleHierarchyRepository.save(roleHierarchyEntity);

        if (savedEntity.getIsActive()) {
            deactivateAllOtherHierarchies(savedEntity.getId());
            reloadRoleHierarchyBean(); // 런타임에 RoleHierarchyImpl 빈 갱신
        }
        log.info("Created RoleHierarchyEntity with ID: {}", savedEntity.getId());
        return savedEntity;
    }

    /**
     * 기존 역할 계층 설정을 업데이트합니다.
     * (이전 응답에서 제공된 updateRoleHierarchy 메서드 내용 그대로)
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

        validateHierarchyString(roleHierarchyEntity.getHierarchyString());

        existingEntity.setHierarchyString(roleHierarchyEntity.getHierarchyString());
        existingEntity.setDescription(roleHierarchyEntity.getDescription());
        existingEntity.setIsActive(roleHierarchyEntity.getIsActive());

        RoleHierarchyEntity updatedEntity = roleHierarchyRepository.save(existingEntity);

        if (updatedEntity.getIsActive()) {
            deactivateAllOtherHierarchies(updatedEntity.getId());
        }
        reloadRoleHierarchyBean();
        log.info("Updated RoleHierarchyEntity with ID: {}", updatedEntity.getId());
        return updatedEntity;
    }

    /**
     * 특정 역할 계층 설정을 삭제합니다.
     * (이전 응답에서 제공된 deleteRoleHierarchy 메서드 내용 그대로)
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
        reloadRoleHierarchyBean();
        log.info("Deleted RoleHierarchyEntity with ID: {}", id);
    }

    /**
     * 특정 RoleHierarchyEntity를 활성화하고, 나머지 모든 계층 설정을 비활성화합니다.
     * (이전 응답에서 제공된 activateRoleHierarchy 메서드 내용 그대로)
     */
    @Transactional
    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true)
    public void activateRoleHierarchy(Long activeId) {
        List<RoleHierarchyEntity> all = roleHierarchyRepository.findAll();
        for (RoleHierarchyEntity entity : all) {
            entity.setIsActive(Objects.equals(entity.getId(), activeId));
            roleHierarchyRepository.save(entity);
        }
        reloadRoleHierarchyBean();
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
            // ObjectProvider를 통해 RoleHierarchyImpl 빈을 가져와 설정
            roleHierarchy.setHierarchy(hierarchyString); // <<< ObjectProvider 사용
            log.info("RoleHierarchyImpl bean reloaded with new hierarchy: \n{}", hierarchyString);
        } catch (Exception e) {
            log.error("Failed to reload RoleHierarchyImpl bean dynamically. Error: {}", e.getMessage(), e);
        }
    }

    /**
     * 계층 문자열에 포함된 역할 이름들이 DB에 실제로 존재하는 역할들인지 검증합니다.
     * (이전 응답에서 제공된 validateHierarchyString 메서드 내용 그대로)
     */
    private void validateHierarchyString(String hierarchyString) {
        if (hierarchyString == null || hierarchyString.trim().isEmpty()) {
            return;
        }
        Set<String> referencedRoleNames = Arrays.stream(hierarchyString.split("[\\n>]"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());

        Set<String> cleanRoleNames = referencedRoleNames.stream()
                .map(s -> s.startsWith("ROLE_") ? s.substring(5) : s)
                .collect(Collectors.toSet());

        Set<String> existingRoleNames = roleRepository.findAll().stream()
                .map(role -> role.getRoleName().toUpperCase())
                .collect(Collectors.toSet());

        for (String roleName : cleanRoleNames) {
            if (!existingRoleNames.contains(roleName.toUpperCase())) {
                throw new IllegalArgumentException("Hierarchy string contains invalid role name: " + roleName + ". Role does not exist in the database.");
            }
        }
    }

    private void deactivateAllOtherHierarchies(Long currentActiveId) {
        roleHierarchyRepository.findByIsActiveTrue()
                .filter(e -> !e.getId().equals(currentActiveId))
                .ifPresent(e -> {
                    e.setIsActive(false);
                    roleHierarchyRepository.save(e);
                });
    }
}