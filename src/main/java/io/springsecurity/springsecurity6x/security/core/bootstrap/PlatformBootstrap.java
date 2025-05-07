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
public class PlatformBootstrap implements InitializingBean {

    private final SecurityPlatform platform;
    private final PlatformConfig config;
    private final FeatureRegistry registry;

    public PlatformBootstrap(SecurityPlatform platform, PlatformConfig config, FeatureRegistry featureRegistry) {
        this.platform = platform;
        this.config = config;
        this.registry = featureRegistry;
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        List<AuthenticationFlowConfig> flows = config.flows();
        List<AuthenticationFeature> features = registry.getAuthFeaturesFor(flows);

        platform.prepareGlobal(config, features);
        platform.initialize();
    }
}
