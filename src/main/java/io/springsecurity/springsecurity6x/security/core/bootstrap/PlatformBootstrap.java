package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Auto-bootstrap for security platform:
 * SecurityConfig 에서 정의된 PlatformConfig와 FeatureProvider가
 * 이 클래스에서 SecurityPlatform에 전달되어 초기화됩니다.
 */
@Configuration
public class PlatformBootstrap implements InitializingBean {

    private final SecurityPlatform platform;
    private final PlatformConfig config;
    private final FeatureRegistry registry;

    public PlatformBootstrap(SecurityPlatform platform,
                             PlatformConfig config,
                             FeatureRegistry featureRegistry) {
        this.platform = platform;
        this.config = config;
        this.registry = featureRegistry;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        List<AuthenticationFlowConfig> flows = config.getFlows();
        // Registry를 통해 필요한 인증 기능 리스트 획득
        List<AuthenticationFeature> features = registry.getAuthFeaturesFor(flows);
        // Global 준비
        platform.prepareGlobal(config, features);
        platform.initialize();
    }
}
