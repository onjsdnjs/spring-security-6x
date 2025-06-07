package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.ResourcesRepository;
import io.springsecurity.springsecurity6x.admin.service.ResourcesService;
import io.springsecurity.springsecurity6x.entity.Resources;
import io.springsecurity.springsecurity6x.entity.ResourcesRole;
import io.springsecurity.springsecurity6x.entity.Role;
import io.springsecurity.springsecurity6x.security.authz.manager.CustomDynamicAuthorizationManager;
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
public class ResourcesServiceImpl implements ResourcesService {

    private final ResourcesRepository resourcesRepository;
    private final CustomDynamicAuthorizationManager authorizationManager; // CustomDynamicAuthorizationManager 주입

    @Transactional(readOnly = true)
    @Cacheable(value = "resources", key = "#id")
    public Resources getResources(long id) {
        return resourcesRepository.findByIdWithRoles(id)
                .orElseThrow(() -> new IllegalArgumentException("Resources not found with ID: " + id));
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "resources", key = "'allResources'")
    public List<Resources> getResources() {
        return resourcesRepository.findAllResources();
    }

    /**
     * 새로운 Resources를 생성하고 저장합니다. Role 할당 로직 포함.
     * `ResourcesRole` 조인 엔티티를 통해 `Role`과의 관계를 설정합니다.
     * @param resources 생성할 Resources 엔티티
     * @param roles 할당할 Role 엔티티 집합
     * @return 생성된 Resources 엔티티
     */
    @Transactional
    @Caching(
            evict = { @CacheEvict(value = "resources", allEntries = true),
                      @CacheEvict(value = "resourcesUrlRoleMappings", allEntries = true) },
            put = {   @CachePut(value = "resources", key = "#result.id") }
    )
    public Resources createResources(Resources resources, Set<Role> roles) {
        // 중복 resourceName, httpMethod 체크 로직 (필요시)
        if (resourcesRepository.findByResourceNameAndHttpMethod(resources.getResourceName(), resources.getHttpMethod()).isPresent()) {
            throw new IllegalArgumentException("Resources with this name and HTTP method already exists.");
        }

        Resources savedResources = resourcesRepository.save(resources);
        if (roles != null && !roles.isEmpty()) {
            Set<ResourcesRole> resourcesRoles = new HashSet<>();
            for (Role role : roles) {
                resourcesRoles.add(ResourcesRole.builder().resources(savedResources).role(role).build());
            }
            savedResources.setResourcesRoles(resourcesRoles);
            resourcesRepository.save(savedResources);
        }

        // <<< 핵심: 정책 변경 후, PEP에 알려 동적 인가 규칙을 다시 로드하도록 함 >>>
        authorizationManager.reload();
        log.info("Created Resources and reloaded authorization mappings: {}", savedResources.getResourceName());
        return savedResources;
    }

    /**
     * 기존 Resources를 업데이트하고 저장합니다. Role 할당 로직 포함.
     * `ResourcesRole` 조인 엔티티를 통해 `Role`과의 관계를 업데이트합니다.
     * @param resources 업데이트할 Resources 엔티티 (ID 포함)
     * @param roles 할당할 Role 엔티티 집합
     * @return 업데이트된 Resources 엔티티
     */
    @Transactional // 쓰기 작업
    @Caching(
            evict = {
                    @CacheEvict(value = "resources", allEntries = true),
                    @CacheEvict(value = "resourcesUrlRoleMappings", allEntries = true)
            },
            put = { @CachePut(value = "resources", key = "#result.id") }
    )
    public Resources updateResources(Resources resources, Set<Role> roles) {
        // findByIdWithRoles를 사용하여 기존 Resources와 ResourcesRole 관계를 함께 가져옵니다.
        Resources existingResources = resourcesRepository.findByIdWithRoles(resources.getId())
                .orElseThrow(() -> new IllegalArgumentException("Resources not found with ID: " + resources.getId()));
        existingResources.setResourceName(resources.getResourceName());
        existingResources.setHttpMethod(resources.getHttpMethod());
        existingResources.setOrderNum(resources.getOrderNum());
        existingResources.setResourceType(resources.getResourceType());
        existingResources.getResourcesRoles().clear();
        if (roles != null && !roles.isEmpty()) {
            for (Role role : roles) {
                existingResources.getResourcesRoles().add(ResourcesRole.builder().resources(existingResources).role(role).build());
            }
        }
        resourcesRepository.save(existingResources);

        // <<< 핵심: 정책 변경 후, PEP에 알려 동적 인가 규칙을 다시 로드하도록 함 >>>
        authorizationManager.reload();
        log.info("Updated Resources and reloaded authorization mappings: {}", existingResources.getResourceName());
        return existingResources;
    }

    /**
     * Resources를 삭제합니다.
     * 관련 캐시를 무효화하고 동적 권한 매핑을 갱신합니다.
     * @param id 삭제할 Resources ID
     */
    @Transactional // 쓰기 작업
    @Caching(
            evict = {
                    @CacheEvict(value = "resources", allEntries = true),
                    @CacheEvict(value = "resources", key = "#id"), // 특정 ID 캐시 무효화
                    @CacheEvict(value = "resourcesUrlRoleMappings", allEntries = true)
            }
    )
    public void deleteResources(long id) {
        resourcesRepository.deleteById(id);
        authorizationManager.reload(); // 동적 권한 매핑 갱신
        log.info("Deleted Resources ID {} and reloaded authorization mappings.", id);
    }
}