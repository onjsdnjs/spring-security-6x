package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.AuthFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.StateFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * SecurityConfigurer 인스턴스 목록을 제공하는 기본 구현체입니다.
 * Spring 컨텍스트에서 SecurityConfigurer 빈들을 수집하고,
 * FeatureRegistry를 통해 동적으로 Feature 관련 ConfigurerAdapter들을 추가합니다.
 */
@Component
@Slf4j
public final class DefaultSecurityConfigurerProvider implements SecurityConfigurerProvider {

    private final List<SecurityConfigurer> collectedBaseConfigurers;
    private final FeatureRegistry featureRegistry;
    private final ApplicationContext applicationContext; // AsepConfigurer 등 특정 빈 직접 참조 위해 (현재는 사용되지 않음)

    @Autowired
    public DefaultSecurityConfigurerProvider(
            List<SecurityConfigurer> baseConfigurers, // Spring 컨텍스트에서 모든 SecurityConfigurer 빈 주입
            FeatureRegistry featureRegistry,
            ApplicationContext applicationContext) {
        this.collectedBaseConfigurers = (baseConfigurers != null) ? new ArrayList<>(baseConfigurers) : new ArrayList<>();
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "FeatureRegistry cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
        log.info("DefaultSecurityConfigurerProvider initialized with {} base configurers.", this.collectedBaseConfigurers.size());
        if (log.isDebugEnabled()) {
            this.collectedBaseConfigurers.forEach(cfg -> log.debug("  - Detected Base Configurer: {}", cfg.getClass().getName()));
        }
    }

    @Override
    public List<SecurityConfigurer> getGlobalConfigurers(PlatformContext platformContext, PlatformConfig platformConfig) {
        // 애플리케이션 컨텍스트에서 주입된 모든 SecurityConfigurer 빈들을 "전역" Configurer로 간주하여 반환합니다.
        // 이들은 플랫폼 초기화 시점에 init()이 호출되고, 각 플로우 설정 시점에 configure()가 호출됩니다.
        // AsepConfigurer, GlobalConfigurer, FlowConfigurer 등이 여기에 포함됩니다.
        log.debug("DefaultSecurityConfigurerProvider: Providing {} base/global configurers.", collectedBaseConfigurers.size());
        return List.copyOf(this.collectedBaseConfigurers);
    }

    @Override
    public List<SecurityConfigurer> getFlowSpecificConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig,
            HttpSecurity httpForScope) {
        Objects.requireNonNull(httpForScope, "HttpSecurity (httpForScope) cannot be null for getFlowSpecificConfigurers");

        List<SecurityConfigurer> flowSpecificAdapters = new ArrayList<>();
        AuthenticationFlowConfig currentFlow = httpForScope.getSharedObject(AuthenticationFlowConfig.class);

        if (currentFlow == null) {
            log.warn("DefaultSecurityConfigurerProvider: AuthenticationFlowConfig not found in HttpSecurity sharedObjects for hash {}. " +
                            "Cannot determine flow-specific features. No feature adapters will be added for this scope.",
                    httpForScope.hashCode());
            return Collections.emptyList(); // 이 HttpSecurity에 매핑된 플로우 정보가 없으면, 특화된 어댑터는 없음
        }

        log.debug("DefaultSecurityConfigurerProvider: Determining flow-specific configurer adapters for flow '{}' (HttpSecurity hash: {})",
                currentFlow.getTypeName(), httpForScope.hashCode());

        // 현재 Flow에 정의된 인증 단계(AuthFeature) 및 상태 관리(StateFeature)에 대한 어댑터만 추가
        if (featureRegistry != null) {
            // 현재 플로우 하나만 포함하는 리스트를 전달하여 해당 플로우에 필요한 Feature만 가져오도록 함
            List<AuthenticationFlowConfig> singleFlowList = Collections.singletonList(currentFlow);

            featureRegistry.getAuthFeaturesFor(singleFlowList)
                    .forEach(feature -> {
                        flowSpecificAdapters.add(new AuthFeatureConfigurerAdapter(feature));
                        log.debug("  Added AuthFeatureConfigurerAdapter for feature '{}' relevant to flow '{}'.",
                                feature.getId(), currentFlow.getTypeName());
                    });

            featureRegistry.getStateFeaturesFor(singleFlowList)
                    .forEach(stateFeature -> {
                        flowSpecificAdapters.add(new StateFeatureConfigurerAdapter(stateFeature, platformContext));
                        log.debug("  Added StateFeatureConfigurerAdapter for state feature '{}' relevant to flow '{}'.",
                                stateFeature.getId(), currentFlow.getTypeName());
                    });
        } else {
            log.warn("DefaultSecurityConfigurerProvider: FeatureRegistry is null. Cannot add feature-based adapters for flow '{}'.", currentFlow.getTypeName());
        }

        log.debug("DefaultSecurityConfigurerProvider: Providing {} flow-specific configurer adapters for flow '{}'.",
                flowSpecificAdapters.size(), currentFlow.getTypeName());
        return List.copyOf(flowSpecificAdapters);
    }
}
