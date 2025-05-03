package io.springsecurity.springsecurity6x.security.core.config;

import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeatureRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 인증 기능 레지스트리(AuthenticationFeatureRegistry)를 사용하여
 * DSL로 정의된 PlatformConfig 기반의 모든 인증 흐름을
 * 순차적으로 HttpSecurity에 적용하는 체인입니다.
 *
 * 사용 예:
 *   AuthenticationFeatureRegistry registry = new AuthenticationFeatureRegistry(features);
 *   AuthenticationConfigurerChain chain = new AuthenticationConfigurerChain(registry);
 *   chain.configure(http, platformConfig);
 */
public class AuthenticationConfigurerChain {

    private final AuthenticationFeatureRegistry registry;

    public AuthenticationConfigurerChain(AuthenticationFeatureRegistry registry) {
        this.registry = registry;
    }
    /**
     * HttpSecurity에 플랫폼 설정(PlatformConfig)에 정의된 모든 인증 플로우를 적용합니다.
     *
     * @param http   HttpSecurity 인스턴스
     * @param config DSL로 정의된 글로벌 및 각 인증 플로우 설정을 담은 PlatformConfig
     * @throws Exception 적용 중 오류 발생 시
     */
    public void configure(HttpSecurity http, PlatformConfig config) throws Exception {
        registry.configure(http, config);
    }
}

