package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;

/**
 * 보안 체인 구성 단계별 책임을 분리하는 인터페이스
 */
public interface SecurityConfigurer {
    /** 전역(Global) 설정 적용 단계 */
    default void init(FlowContext ctx, PlatformConfig cfg) {}
    /** 인증 흐름 및 단계를 적용하는 단계 */
    default void configure(FlowContext ctx ) throws Exception {}
}
