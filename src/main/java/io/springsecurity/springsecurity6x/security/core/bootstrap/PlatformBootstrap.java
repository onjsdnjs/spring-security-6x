package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Auto-bootstrap for security platform:
 * SecurityConfig 에서 정의된 PlatformConfig와 FeatureProvider가
 * 이 클래스에서 SecurityPlatform에 전달되어 초기화됩니다.
 */
@Configuration
@Import(FeatureProvider.class)
public class PlatformBootstrap implements InitializingBean {
    private final SecurityPlatform platform;
    private final FeatureProvider provider;
    private final PlatformConfig config;

    public PlatformBootstrap(SecurityPlatform platform,
                             FeatureProvider provider,
                             PlatformConfig config) {
        this.platform = platform;
        this.provider = provider;
        this.config = config;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        platform.prepareGlobal(config, provider.getFeatures());
        platform.initialize();
    }
}
