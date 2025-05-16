package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContextFactory;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.validator.DslValidatorService;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;

import java.util.List;

/**
 * Auto-bootstrap for security platform:
 * SecurityConfig 에서 정의된 PlatformConfig와 FeatureProvider가
 * 이 클래스에서 SecurityPlatform에 전달되어 초기화됩니다.
 */
@Slf4j
@RequiredArgsConstructor
public class PlatformBootstrap implements InitializingBean {

    private final SecurityPlatform platform;
    private final PlatformConfig config;
    private final FeatureRegistry registry;
    private final DslValidatorService dslValidatorService;
    private final FlowContextFactory flowContextFactory;
    private final PlatformContext platformContext;

    @Override
    public void afterPropertiesSet() throws Exception {
        log.info("PlatformBootstrap: Starting DSL configuration validation...");
        try {
            dslValidatorService.validate(config, "PlatformSecurityConfig.java (DSL)");

        } catch (DslConfigurationException e) {
            log.error("DSL 유효성 검사 실패로 서버 기동을 중단합니다.", e);
            throw e;
        }
        log.info("PlatformBootstrap: DSL configuration validation passed.");


        // 1. 플랫폼 전역 준비 (기존 로직)
        List<AuthenticationFlowConfig> flows = config.getFlows();
        List<AuthenticationFeature> features = registry.getAuthFeaturesFor(flows);
        platform.prepareGlobal(config, features);

        // 2. 플랫폼 초기화 (기존 로직)
        platform.initialize();
        log.info("PlatformBootstrap: Security platform initialized successfully.");
    }
}
