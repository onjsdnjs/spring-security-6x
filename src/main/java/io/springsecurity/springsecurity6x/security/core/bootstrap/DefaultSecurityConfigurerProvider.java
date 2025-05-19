package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.AuthFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.StateFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Component
@Slf4j
public final class DefaultSecurityConfigurerProvider implements SecurityConfigurerProvider {

    private final List<SecurityConfigurer> applicationWideConfigurers;
    private final FeatureRegistry featureRegistry;
    private final ApplicationContext applicationContext;

    @Autowired
    public DefaultSecurityConfigurerProvider(
            List<SecurityConfigurer> collectedApplicationWideConfigurers,
            FeatureRegistry featureRegistry,
            ApplicationContext applicationContext) {

        this.applicationWideConfigurers = (collectedApplicationWideConfigurers != null) ?
                List.copyOf(collectedApplicationWideConfigurers) : Collections.emptyList();
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "FeatureRegistry cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");

        log.info("DefaultSecurityConfigurerProvider initialized with {} application-wide configurers.", this.applicationWideConfigurers.size());
        if (log.isDebugEnabled()) {
            this.applicationWideConfigurers.forEach(cfg -> log.debug("  - Detected Application-Wide Configurer: {}", cfg.getClass().getName()));
        }
    }

    @Override
    public List<SecurityConfigurer> getConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig) {
        Objects.requireNonNull(platformContext, "PlatformContext cannot be null");
        Objects.requireNonNull(platformConfig, "PlatformConfig cannot be null");

        // 1. 애플리케이션 전역 Configurer (Spring 컨텍스트에서 수집된 빈들)
        List<SecurityConfigurer> effectiveConfigurers = new ArrayList<>(this.applicationWideConfigurers);
        log.debug("DefaultSecurityConfigurerProvider: Starting with {} application-wide configurers.", effectiveConfigurers.size());

        // 2. FeatureRegistry를 통해 동적으로 생성되는 Feature 기반 Configurer Adapter들 추가
        // 이 Adapter 들은 PlatformConfig에 정의된 모든 Flow에 대해 생성될 수 있으며,
        // 각 Adapter의 configure(FlowContext) 메소드 내부에서 현재 Flow에 적용될지 여부를 판단함.
        if (featureRegistry != null && !CollectionUtils.isEmpty(platformConfig.getFlows())) {
            featureRegistry.getAuthFeaturesFor(platformConfig.getFlows())
                    .forEach(feature -> {
                        effectiveConfigurers.add(new AuthFeatureConfigurerAdapter(feature));
                        log.debug("DefaultSecurityConfigurerProvider: Added AuthFeatureConfigurerAdapter for feature '{}'.", feature.getId());
                    });

            featureRegistry.getStateFeaturesFor(platformConfig.getFlows())
                    .forEach(stateFeature -> {
                        // StateFeatureConfigurerAdapter는 PlatformContext를 필요로 함
                        effectiveConfigurers.add(new StateFeatureConfigurerAdapter(stateFeature, platformContext));
                        log.debug("DefaultSecurityConfigurerProvider: Added StateFeatureConfigurerAdapter for feature '{}'.", stateFeature.getId());
                    });
        } else {
            log.warn("DefaultSecurityConfigurerProvider: FeatureRegistry or PlatformConfig.getFlows() is null/empty. " +
                    "No dynamic feature-based configurers (AuthFeature, StateFeature) will be added.");
        }

        // AsepConfigurer는 applicationWideConfigurers에 이미 포함되어 있음 (싱글톤 빈으로 가정).
        // AsepConfigurer의 configure(FlowContext) 메소드가 각 Flow에 대해 호출될 때,
        // 해당 Flow의 HttpSecurity.sharedObjects에 저장된 XxxAsepAttributes를 사용하여
        // POJO ASEPFilter를 동적으로 생성하고 추가함.

        log.info("DefaultSecurityConfigurerProvider: Total {} effective configurers prepared.", effectiveConfigurers.size());
        return List.copyOf(effectiveConfigurers); // 최종 리스트를 불변으로 반환
    }
}
