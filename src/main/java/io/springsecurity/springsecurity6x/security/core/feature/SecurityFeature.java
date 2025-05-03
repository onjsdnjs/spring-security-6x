package io.springsecurity.springsecurity6x.security.core.feature;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;

/**
 * 플랫폼에 등록되는 보안 기능(인증/상태/MFA 플로우 등)의
 * 공통 인터페이스입니다.
 *
 * CompositeSecurityFeature 등 구현체가 이 계약을 준수하여
 * PlatformContext를 받아 HttpSecurity를 구성합니다.
 */
public interface SecurityFeature {
    /**
     * 주어진 PlatformContext 에서 HttpSecurity 빌더를 얻어
     * 체인별 설정(인증 단계, 상태 전략, 필터 추가 등)을 수행합니다.
     *
     * @param context 컨텍스트(체인 ID별 HttpSecurity 빌더 제공, 체인 등록 등)
     * @throws Exception 설정 중 예외 발생 시
     */
    void configure(PlatformContext context) throws Exception;
}
