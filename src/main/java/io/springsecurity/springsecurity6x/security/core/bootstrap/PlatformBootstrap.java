package io.springsecurity.springsecurity6x.security.core.bootstrap;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(FeatureProvider.class)
public class PlatformBootstrap implements InitializingBean {
    private final SecurityPlatform platform;
    private final FeatureProvider provider;
    public PlatformBootstrap(SecurityPlatform platform, FeatureProvider provider) {
        this.platform = platform; this.provider = provider;
    }
    @Override
    public void afterPropertiesSet() {
        platform.prepareGlobal(provider.getFeatures());
        platform.initialize();
    }
}
