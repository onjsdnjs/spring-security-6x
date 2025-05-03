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
    private final PlatformConfig config;
    private final FeatureProvider provider;

    public PlatformBootstrap(SecurityPlatform platform,
                             PlatformConfig config,
                             FeatureProvider provider) {
        this.platform = platform;
        this.config = config;
        this.provider = provider;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        platform.prepareGlobal(config, provider.getFeatures());
        platform.initialize();
    }
}
