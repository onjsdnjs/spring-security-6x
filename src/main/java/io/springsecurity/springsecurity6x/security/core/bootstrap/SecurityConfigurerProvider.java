package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;

import java.util.List;

/**
 * 플랫폼에서 사용될 SecurityConfigurer 인스턴스들을 제공하는 인터페이스입니다.
 * SecurityConfigurerOrchestrator에 의해 사용됩니다.
 */
public interface SecurityConfigurerProvider {

    /**
     * 적용할 SecurityConfigurer 리스트를 반환합니다.
     * 이 메소드는 전역 초기화(init) 단계와 각 Flow별 구성(configure) 단계 모두에서 호출될 수 있습니다.
     * 반환되는 Configurer 들은 자신의 init/configure 메소드 내에서
     * 전달받는 PlatformContext 또는 FlowContext를 통해 적용 범위를 결정해야 합니다.
     *
     * @param platformContext 플랫폼 전역 컨텍스트
     * @param platformConfig 플랫폼 전역 설정
     * @return 적용할 SecurityConfigurer 리스트
     */
    List<SecurityConfigurer> getConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig
    );
}