package io.springsecurity.springsecurity6x.security.service;

import io.springsecurity.springsecurity6x.security.authz.persist.UrlRoleMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * 동적 인가 정보를 제공하는 서비스.
 * 데이터베이스로부터 URL-역할 매핑을 조회하고 캐싱하는 책임을 가집니다.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DynamicAuthorizationService {

    private final UrlRoleMapper delegate;

    /**
     * URL과 역할 매핑 정보를 반환합니다.
     * 결과를 'resourcesUrlRoleMappings' 캐시에 저장하여 반복적인 DB 조회를 방지합니다.
     * @return URL 패턴을 키로, 접근 제어 표현식을 값으로 갖는 Map
     */
    @Cacheable(value = "resourcesUrlRoleMappings", key = "'all'")
    public Map<String, String> getUrlRoleMappings() {
        log.info("Loading dynamic URL-Role mappings from the data source...");
        Map<String, String> mappings = delegate.getUrlRoleMappings();
        log.debug("Loaded {} URL-Role mappings.", mappings.size());
        return mappings;
    }

    /**
     * 동적 인가와 관련된 모든 캐시를 무효화합니다.
     * 이 메서드는 인가 규칙이 변경되었을 때 호출되어야 합니다.
     */
    @CacheEvict(value = "resourcesUrlRoleMappings", allEntries = true)
    public void clearCache() {
        log.info("Cache 'resourcesUrlRoleMappings' has been cleared due to authorization rule changes.");
        // 향후 연관된 다른 캐시(예: 사용자 권한 캐시)가 있다면 함께 무효화하는 로직 추가 가능
        // 예: cacheManager.getCache("usersWithAuthorities").clear();
    }
}