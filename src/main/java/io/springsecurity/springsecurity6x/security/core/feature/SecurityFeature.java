package io.springsecurity.springsecurity6x.security.core.feature;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;

/**
 * 플랫폼 초기화 시 사용되는 단일 책임 SPI.
 * CompositeSecurityFeature 처럼, 이 인터페이스를 구현하면
 * PlatformContext를 통해 직접 HttpSecurity 체인을 등록할 수 있습니다.
 */
public interface SecurityFeature {
    /**
     * PlatformContext에서 제공하는 DSL 결과(PlatformConfig)를
     * 바탕으로 HttpSecurity 빌더를 생성하고 SecurityFilterChain을 등록합니다.
     *
     * @param ctx  플랫폼 컨텍스트(DSL 결과 + 빈 팩토리 등 제공)
     * @throws Exception 설정 오류 시
     */
    void configure(PlatformContext ctx) throws Exception;
}