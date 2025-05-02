package io.springsecurity.springsecurity6x.security.init;

import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;
import java.util.List;

/**
 * 최종적으로 구성된 SecurityFilterChain 들을 담는 플랫폼 객체.
 * 인증 방식 및 상태 전략 조합에 따라 복수 개의 필터 체인을 가질 수 있음.
 */
public class IdentityPlatform {

    private final List<SecurityFilterChain> filterChains;

    public IdentityPlatform(List<SecurityFilterChain> filterChains) {
        this.filterChains = filterChains;
    }

    /**
     * 구성된 모든 SecurityFilterChain 목록을 반환한다.
     */
    public List<SecurityFilterChain> getFilterChains() {
        return Collections.unmodifiableList(filterChains);
    }

    // TODO: 향후 전략 메타데이터, 체인 조회, Spring 등록용 메서드 등 확장 가능
}
