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

    private final List<SecurityConfigurer> baseConfigurers; // GlobalConfigurer, AsepConfigurer 등 Spring 컨텍스트의 모든 SecurityConfigurer 빈
    private final FeatureRegistry featureRegistry;
    private final ApplicationContext applicationContext; // 로깅 또는 디버깅용으로만 유지, 직접적인 기능 의존성 X

    /**
     * 생성자.
     * @param allCollectedConfigurers Spring 컨텍스트에 등록된 모든 SecurityConfigurer 빈들.
     * (예: GlobalConfigurer, AsepConfigurer 등)
     * Spring이 자동으로 List에 주입해줍니다.
     * @param featureRegistry 플랫폼의 FeatureRegistry.
     * @param applicationContext ApplicationContext (주로 로깅/디버깅 또는 매우 예외적인 경우에 사용).
     */
    @Autowired
    public DefaultSecurityConfigurerProvider(
            List<SecurityConfigurer> allCollectedConfigurers, // null일 수 있음을 명시적 처리
            FeatureRegistry featureRegistry,
            ApplicationContext applicationContext) {
        this.baseConfigurers = (allCollectedConfigurers != null) ? List.copyOf(allCollectedConfigurers) : Collections.emptyList();
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "FeatureRegistry cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");

        log.info("DefaultSecurityConfigurerProvider initialized with {} base configurers.", this.baseConfigurers.size());
        if (log.isDebugEnabled()) {
            this.baseConfigurers.forEach(cfg -> log.debug("  - Detected Base Configurer: {}", cfg.getClass().getName()));
        }
    }

    @Override
    public List<SecurityConfigurer> getConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig) {
        Objects.requireNonNull(platformContext, "PlatformContext cannot be null");
        Objects.requireNonNull(platformConfig, "PlatformConfig cannot be null");

        List<SecurityConfigurer> allEffectiveConfigurers = new ArrayList<>(this.baseConfigurers);

        // FeatureRegistry를 통해 동적으로 생성되는 Adapter들을 추가
        // 이 Adapter들은 특정 Flow에 대한 HttpSecurity를 직접 구성하는 것이 아니라,
        // 내부적으로 Feature의 apply(HttpSecurity, PlatformContext) 등을 호출하는 역할을 함.
        // 각 Feature의 apply 메소드는 FlowContext의 HttpSecurity에 접근하여 작업을 수행.
        // 따라서, 이 Provider는 Feature 자체나 그 Adapter를 반환하고,
        // Orchestrator가 각 Flow에 대해 이들을 실행시킴.

        if (featureRegistry != null && platformConfig != null && !CollectionUtils.isEmpty(platformConfig.getFlows())) {
            // AuthFeature들에 대한 Adapter 추가
            featureRegistry.getAuthFeaturesFor(platformConfig.getFlows())
                    .forEach(feature -> {
                        allEffectiveConfigurers.add(new AuthFeatureConfigurerAdapter(feature));
                        log.debug("DefaultSecurityConfigurerProvider: Added AuthFeatureConfigurerAdapter for feature '{}'", feature.getId());
                    });

            // StateFeature들에 대한 Adapter 추가
            featureRegistry.getStateFeaturesFor(platformConfig.getFlows())
                    .forEach(stateFeature -> {
                        allEffectiveConfigurers.add(new StateFeatureConfigurerAdapter(stateFeature, platformContext));
                        log.debug("DefaultSecurityConfigurerProvider: Added StateFeatureConfigurerAdapter for feature '{}'", stateFeature.getId());
                    });
        } else {
            log.warn("DefaultSecurityConfigurerProvider: FeatureRegistry, PlatformConfig, or PlatformConfig.getFlows() is null/empty. " +
                    "No feature-based configurers (AuthFeature, StateFeature) will be added.");
        }

        // 최종적으로 모든 Configurer (기본 빈 + 동적 생성 Adapter) 리스트 반환
        // 순서 정렬은 SecurityConfigurerOrchestrator에서 수행
        log.info("DefaultSecurityConfigurerProvider: Total {} configurers provided (Base: {}, FeatureAdapters: {}).",
                allEffectiveConfigurers.size(),
                this.baseConfigurers.size(),
                allEffectiveConfigurers.size() - this.baseConfigurers.size());
        return List.copyOf(allEffectiveConfigurers); // 불변 리스트 반환
    }
}
