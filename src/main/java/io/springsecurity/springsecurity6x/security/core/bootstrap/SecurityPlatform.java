package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.feature.SecurityFeature;

import java.util.List;

/**
 * 플랫폼(SecurityPlatform) 인터페이스:
 * 등록된 SecurityFeature를 사용하여
 * SecurityFilterChain을 생성 및 초기화합니다.
 */
public interface SecurityPlatform {
    /**
     * FeatureProvider로부터 제공된
     * SecurityFeature 리스트를 설정합니다.
     *
     * @param features 등록된 SecurityFeature 리스트
     */
    void prepareGlobal(List<SecurityFeature> features);

    /**
     * 등록된 모든 SecurityFeature.configure()를 호출하여
     * HttpSecurity 기반의 SecurityFilterChain을 생성 및 등록합니다.
     */
    void initialize();
}
