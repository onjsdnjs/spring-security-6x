package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.SecurityFeature;

import java.util.List;

/**
 * 플랫폼(SecurityPlatform) 인터페이스:
 * DSL로 정의된 PlatformConfig와
 * 등록된 AuthenticationFeature를 사용하여
 * Spring Security 구성을 초기화합니다.
 */
public interface SecurityPlatform {

    /**
     * DSL로 수집된 PlatformConfig와 AuthenticationFeature 리스트를 설정합니다.
     */
    void prepareGlobal(PlatformConfig config, List<AuthenticationFeature> features);

    /**
     * HttpSecurity 기반으로 SecurityFilterChain을 생성 및 등록합니다.
     */
    void initialize() throws Exception;
}
