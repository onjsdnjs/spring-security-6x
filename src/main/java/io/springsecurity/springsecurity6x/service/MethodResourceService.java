package io.springsecurity.springsecurity6x.service;

import io.springsecurity.springsecurity6x.entity.MethodResource;
import io.springsecurity.springsecurity6x.admin.repository.MethodResourceRepository;
import io.springsecurity.springsecurity6x.entity.Role; // Role 엔티티 임포트
import io.springsecurity.springsecurity6x.entity.Permission; // Permission 엔티티 임포트
import io.springsecurity.springsecurity6x.entity.MethodResourceRole; // MethodResourceRole 조인 엔티티 임포트
import io.springsecurity.springsecurity6x.entity.MethodResourcePermission; // MethodResourcePermission 조인 엔티티 임포트

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

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class MethodResourceService {

    private final MethodResourceRepository methodResourceRepository;

    /**
     * 새로운 MethodResource를 생성하고 저장합니다. 역할 및 권한 할당 로직 포함.
     * `MethodResourceRole`과 `MethodResourcePermission` 조인 엔티티를 통해 관계를 설정합니다.
     * @param methodResource 생성할 MethodResource 엔티티
     * @param roles 할당할 Role 엔티티 집합
     * @param permissions 할당할 Permission 엔티티 집합
     * @return 생성된 MethodResource 엔티티
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "methodResources", allEntries = true) // 모든 메서드 리소스 캐시 무효화
            },
            put = { @CachePut(value = "methodResources", key = "#result.id") } // 특정 ID로 캐시 갱신
    )
    public MethodResource createMethodResource(MethodResource methodResource, Set<Role> roles, Set<Permission> permissions) {
        // 중복 체크 로직 (className, methodName, httpMethod 조합)
        if (methodResourceRepository.findByClassNameAndMethodNameAndHttpMethod(
                methodResource.getClassName(), methodResource.getMethodName(), methodResource.getHttpMethod()).isPresent()) {
            throw new IllegalArgumentException("MethodResource with className, methodName, httpMethod already exists.");
        }

        MethodResource savedResource = methodResourceRepository.save(methodResource); // 먼저 저장하여 ID를 얻음

        // MethodResourceRole 조인 엔티티 생성 및 연결
        if (roles != null && !roles.isEmpty()) {
            Set<MethodResourceRole> methodResourceRoles = new HashSet<>();
            for (Role role : roles) {
                methodResourceRoles.add(MethodResourceRole.builder().methodResource(savedResource).role(role).build());
            }
            savedResource.setMethodResourceRoles(methodResourceRoles); // 엔티티에 조인 엔티티 설정
        }

        // MethodResourcePermission 조인 엔티티 생성 및 연결
        if (permissions != null && !permissions.isEmpty()) {
            Set<MethodResourcePermission> methodResourcePermissions = new HashSet<>();
            for (Permission permission : permissions) {
                methodResourcePermissions.add(MethodResourcePermission.builder().methodResource(savedResource).permission(permission).build());
            }
            savedResource.setMethodResourcePermissions(methodResourcePermissions); // 엔티티에 조인 엔티티 설정
        }

        // 관계 반영을 위해 다시 저장
        MethodResource finalSavedResource = methodResourceRepository.save(savedResource);
        log.info("Created MethodResource: {}.{} with ID: {}", savedResource.getClassName(), savedResource.getMethodName(), savedResource.getId());
        return finalSavedResource;
    }

    /**
     * ID로 MethodResource를 조회합니다.
     * @param id 조회할 MethodResource ID
     * @return 해당 MethodResource (Optional)
     */
    @Cacheable(value = "methodResources", key = "#id")
    public Optional<MethodResource> getMethodResource(Long id) {
        // findByIdWithRolesAndPermissions 메서드 추가 (MethodResourceRepository에)
        return methodResourceRepository.findByIdWithRolesAndPermissions(id);
    }

    /**
     * 클래스명, 메서드명, HTTP 메서드를 기준으로 MethodResource를 조회합니다.
     * @param className 클래스명
     * @param methodName 메서드명
     * @param httpMethod HTTP 메서드
     * @return 해당 MethodResource (Optional)
     */
    @Cacheable(value = "methodResources", key = "#className + ':' + #methodName + ':' + #httpMethod")
    public Optional<MethodResource> getMethodResourceBySignature(String className, String methodName, String httpMethod) {
        // 이 쿼리에서도 Role과 Permission 정보를 함께 가져오도록 쿼리 수정 필요
        return methodResourceRepository.findByClassNameAndMethodNameAndHttpMethod(className, methodName, httpMethod);
    }

    /**
     * 모든 MethodResource를 orderNum 순으로 정렬하여 조회합니다.
     * @return MethodResource 리스트
     */
    @Cacheable(value = "methodResources", key = "'allMethodResources'")
    public List<MethodResource> getAllMethodResources() {
        // findAllByOrderByOrderNumAsc 쿼리 수정 (Roles 및 Permissions 함께 가져오도록)
        return methodResourceRepository.findAllByOrderByOrderNumAsc();
    }

    /**
     * MethodResource를 업데이트합니다. 역할 및 권한 할당 로직 포함.
     * `MethodResourceRole`과 `MethodResourcePermission` 조인 엔티티를 통해 관계를 업데이트합니다.
     * @param methodResource 업데이트할 MethodResource 엔티티 (ID 포함)
     * @param roles 할당할 Role 엔티티 집합
     * @param permissions 할당할 Permission 엔티티 집합
     * @return 업데이트된 MethodResource 엔티티
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "methodResources", allEntries = true)
            },
            put = { @CachePut(value = "methodResources", key = "#result.id") }
    )
    public MethodResource updateMethodResource(MethodResource methodResource, Set<Role> roles, Set<Permission> permissions) {
        MethodResource existingResource = methodResourceRepository.findByIdWithRolesAndPermissions(methodResource.getId())
                .orElseThrow(() -> new IllegalArgumentException("MethodResource with ID " + methodResource.getId() + " not found for update."));

        existingResource.setMethodName(methodResource.getMethodName());
        existingResource.setClassName(methodResource.getClassName());
        existingResource.setAccessExpression(methodResource.getAccessExpression());
        existingResource.setOrderNum(methodResource.getOrderNum());
        existingResource.setHttpMethod(methodResource.getHttpMethod());

        // 기존 MethodResourceRole 관계 제거 (orphanRemoval = true 덕분에 가능)
        existingResource.getMethodResourceRoles().clear();
        // 새로운 MethodResourceRole 조인 엔티티 생성 및 연결
        if (roles != null && !roles.isEmpty()) {
            for (Role role : roles) {
                existingResource.getMethodResourceRoles().add(MethodResourceRole.builder().methodResource(existingResource).role(role).build());
            }
        }

        // 기존 MethodResourcePermission 관계 제거 (orphanRemoval = true 덕분에 가능)
        existingResource.getMethodResourcePermissions().clear();
        // 새로운 MethodResourcePermission 조인 엔티티 생성 및 연결
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission permission : permissions) {
                existingResource.getMethodResourcePermissions().add(MethodResourcePermission.builder().methodResource(existingResource).permission(permission).build());
            }
        }

        MethodResource updatedResource = methodResourceRepository.save(existingResource); // 변경사항 저장
        log.info("Updated MethodResource: {}.{} with ID: {}", updatedResource.getClassName(), updatedResource.getMethodName(), updatedResource.getId());
        return updatedResource;
    }

    /**
     * ID로 MethodResource를 삭제합니다.
     * 캐시를 무효화합니다.
     * @param id 삭제할 MethodResource ID
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "methodResources", allEntries = true),
                    @CacheEvict(value = "methodResources", key = "#id") // 특정 ID 캐시 무효화
            }
    )
    public void deleteMethodResource(Long id) {
        methodResourceRepository.deleteById(id);
        log.info("Deleted MethodResource ID: {}", id);
    }
}
