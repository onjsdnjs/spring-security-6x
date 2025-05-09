package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;

/**
 * 인증 단계 DSL 컴포넌터 인터페이스
 * - toConfig(): 설정 객체 반환
 * - order(): 실행 순서 반환
 */
public interface StepDslConfigurer {
    AuthenticationStepConfig toConfig();
    int order();
}
