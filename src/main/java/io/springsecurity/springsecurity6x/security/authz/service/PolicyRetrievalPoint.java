package io.springsecurity.springsecurity6x.security.authz.service;

import io.springsecurity.springsecurity6x.entity.policy.Policy;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;

import java.util.List;

/**
 * PRP (Policy Retrieval Point): 정책 검색 지점.
 * PDP의 요청에 따라 저장소(DB)에서 적용 가능한 정책들을 조회하여 반환하는 책임.
 */
public interface PolicyRetrievalPoint {
    /**
     * 적용 가능한 모든 URL 정책을 조회합니다.
     * 결과는 캐시되며, 정책 변경 시 'urlPolicies' 캐시가 무효화되어야 합니다.
     * @return 적용 가능한 정책 목록 (우선순위에 따라 정렬됨)
     */
    @Cacheable(value = "urlPolicies", key = "'allUrlPolicies'")
    List<Policy> findUrlPolicies();

    /**
     * URL 정책 캐시를 모두 무효화합니다.
     */
    @CacheEvict(value = "urlPolicies", allEntries = true)
    void clearUrlPoliciesCache();
}