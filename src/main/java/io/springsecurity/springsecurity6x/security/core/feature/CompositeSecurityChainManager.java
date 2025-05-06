package io.springsecurity.springsecurity6x.security.core.feature;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.impl.CompositeSecurityFeature;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * CompositeSecurityFeature 빈이 모두 생성된 후 자동으로 configure()를 호출하여
 * 실제 SecurityFilterChain을 생성하고 PlatformContext에 등록합니다.
 */
@Component
public class CompositeSecurityChainManager implements SmartInitializingSingleton {

    private final List<CompositeSecurityFeature> features;
    private final PlatformContext context;

    public CompositeSecurityChainManager(List<CompositeSecurityFeature> features,
                                         PlatformContext context) {
        this.features = features;
        this.context = context;
    }

    @Override
    public void afterSingletonsInstantiated() {
        features.forEach(feature -> {
            try {
                feature.configure(context);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to initialize security chain for flow: " + feature.id(), e);
            }
        });
    }
}
