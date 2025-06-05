package io.springsecurity.springsecurity6x.service;

import io.springsecurity.springsecurity6x.entity.MethodResource;
import io.springsecurity.springsecurity6x.repository.MethodResourceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class MethodResourceService {

    private final MethodResourceRepository methodResourceRepository;

    /**
     * 새로운 MethodResource를 생성하고 저장합니다.
     * 캐시를 무효화하여 최신 정보를 반영합니다.
     * @param methodResource 생성할 MethodResource 엔티티
     * @return 생성된 MethodResource 엔티티
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "methodResources", allEntries = true) // 모든 메서드 리소스 캐시 무효화
            },
            put = { @CachePut(value = "methodResources", key = "#result.id") } // 특정 ID로 캐시 갱신
    )
    public MethodResource createMethodResource(MethodResource methodResource) {
        // 중복 체크 로직 (className, methodName, httpMethod 조합)
        if (methodResourceRepository.findByClassNameAndMethodNameAndHttpMethod(
                methodResource.getClassName(), methodResource.getMethodName(), methodResource.getHttpMethod()).isPresent()) {
            throw new IllegalArgumentException("MethodResource with className, methodName, httpMethod already exists.");
        }
        MethodResource savedResource = methodResourceRepository.save(methodResource);
        log.info("Created MethodResource: {}", savedResource.getClassName() + "." + savedResource.getMethodName());
        return savedResource;
    }

    /**
     * ID로 MethodResource를 조회합니다.
     * @param id 조회할 MethodResource ID
     * @return 해당 MethodResource (Optional)
     */
    @Cacheable(value = "methodResources", key = "#id")
    public Optional<MethodResource> getMethodResource(Long id) {
        return methodResourceRepository.findById(id);
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
        return methodResourceRepository.findByClassNameAndMethodNameAndHttpMethod(className, methodName, httpMethod);
    }

    /**
     * 모든 MethodResource를 orderNum 순으로 정렬하여 조회합니다.
     * @return MethodResource 리스트
     */
    @Cacheable(value = "methodResources", key = "'allMethodResources'")
    public List<MethodResource> getAllMethodResources() {
        return methodResourceRepository.findAllByOrderByOrderNumAsc();
    }

    /**
     * MethodResource를 업데이트합니다.
     * 캐시를 무효화하여 최신 정보를 반영합니다.
     * @param methodResource 업데이트할 MethodResource 엔티티 (ID 포함)
     * @return 업데이트된 MethodResource 엔티티
     */
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "methodResources", allEntries = true)
            },
            put = { @CachePut(value = "methodResources", key = "#result.id") }
    )
    public MethodResource updateMethodResource(MethodResource methodResource) {
        if (!methodResourceRepository.existsById(methodResource.getId())) {
            throw new IllegalArgumentException("MethodResource with ID " + methodResource.getId() + " not found for update.");
        }
        MethodResource updatedResource = methodResourceRepository.save(methodResource);
        log.info("Updated MethodResource: {}", updatedResource.getClassName() + "." + updatedResource.getMethodName());
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
                    @CacheEvict(value = "methodResources", allEntries = true)
            }
    )
    public void deleteMethodResource(Long id) {
        methodResourceRepository.deleteById(id);
        log.info("Deleted MethodResource ID: {}", id);
    }
}
