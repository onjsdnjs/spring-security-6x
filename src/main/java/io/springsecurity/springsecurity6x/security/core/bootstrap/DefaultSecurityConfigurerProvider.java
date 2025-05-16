package io.springsecurity.springsecurity6x.security.core.bootstrap;


import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.AuthFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.StateFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * SecurityConfigurer 인스턴스 목록을 제공하는 기본 구현체입니다.
 * 이 클래스는 다양한 유형의 SecurityConfigurer (예: 기본, DSL 기반, Feature 기반)를 생성하고 반환합니다.
 */
@Component
public class DefaultSecurityConfigurerProvider implements SecurityConfigurerProvider {

    private final List<SecurityConfigurer> baseConfigurers;
    private final FeatureRegistry featureRegistry;

    public DefaultSecurityConfigurerProvider(List<SecurityConfigurer> baseConfigurers,
                                             FeatureRegistry featureRegistry) {
        this.baseConfigurers = new ArrayList<>(baseConfigurers);
        this.featureRegistry = featureRegistry;
    }

    @Override
    public List<SecurityConfigurer> getConfigurers(PlatformContext platformContext,
                                                   PlatformConfig platformConfig) {

        List<SecurityConfigurer> configurers = new ArrayList<>(this.baseConfigurers);
        featureRegistry.getAuthFeaturesFor(platformConfig.getFlows())
                .forEach(feature -> configurers.add(new AuthFeatureConfigurerAdapter(feature)));

        featureRegistry.getStateFeaturesFor(platformConfig.getFlows())
                .forEach(stateFeature -> configurers.add(new StateFeatureConfigurerAdapter(stateFeature, platformContext)));

        return configurers;
    }
}
