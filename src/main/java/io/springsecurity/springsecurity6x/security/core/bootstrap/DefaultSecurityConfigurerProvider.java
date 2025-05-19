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
public final class DefaultSecurityConfigurerProvider implements SecurityConfigurerProvider { // final class

    private final List<SecurityConfigurer> collectedBaseConfigurers; // 주입받거나 검색한 기본 Configurer들
    private final FeatureRegistry featureRegistry;
    private final ApplicationContext applicationContext; // AsepConfigurer 등 특정 빈 직접 참조 위해

    /**
     * 생성자.
     * @param allConfigurers Spring 컨텍스트에 등록된 모든 SecurityConfigurer 빈들 (AsepConfigurer, GlobalConfigurer 등 포함).
     * Spring이 자동으로 List에 주입해줍니다.
     * @param featureRegistry 플랫폼의 FeatureRegistry.
     * @param applicationContext ApplicationContext.
     */
    @Autowired // 생성자 주입
    public DefaultSecurityConfigurerProvider(
            List<SecurityConfigurer> basedConfigurer, // null일 수 있음을 명시
            FeatureRegistry featureRegistry,
            ApplicationContext applicationContext) {
        this.collectedBaseConfigurers = (basedConfigurer != null) ? new ArrayList<>(basedConfigurer) : new ArrayList<>();
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "FeatureRegistry cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
        log.info("DefaultSecurityConfigurerProvider initialized with {} base configurers.", this.collectedBaseConfigurers.size());
    }

    @Override
    public List<SecurityConfigurer> getGlobalConfigurers(PlatformContext platformContext, PlatformConfig platformConfig) {
        // 이미 생성자에서 주입받은 collectedBaseConfigurers를 반환하거나,
        // 여기서 추가적인 로직(예: 플랫폼 설정에 따른 필터링)을 적용할 수 있음.
        // AsepConfigurer와 GlobalConfigurer 등은 여기에 포함되어야 함.
        // featureRegistry 관련 Adapter는 Flow 별로 생성되므로 여기서는 제외하는 것이 적절해 보임.
        // 또는, 이 메소드가 정말 "전역 init"만을 위한 것이라면,
        // Orchestrator의 init 루프에서는 이 메소드 결과를 사용하고,
        // configure 루프에서는 아래 getFlowSpecificConfigurers (또는 새로운 getEffectiveConfigurersForFlow)를 사용.
        // 현재 SecurityConfigurerOrchestrator는 getConfigurers 한번만 호출하므로,
        // 이 메소드가 모든 것을 반환해야 함 (이전 버전과의 호환성).
        // -> SecurityConfigurerOrchestrator를 수정했으므로, 이 메소드는 "베이스"만 반환.
        log.debug("DefaultSecurityConfigurerProvider: Providing {} base configurers for global init.", collectedBaseConfigurers.size());
        return List.copyOf(this.collectedBaseConfigurers); // 불변 리스트 반환
    }

    @Override
    public List<SecurityConfigurer> getFlowSpecificConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig,
            HttpSecurity httpForScope) {
        Objects.requireNonNull(httpForScope, "HttpSecurity (httpForScope) cannot be null for getFlowSpecificConfigurers");

        List<SecurityConfigurer> flowSpecificConfigurers = new ArrayList<>();
        AuthenticationFlowConfig currentFlow = httpForScope.getSharedObject(AuthenticationFlowConfig.class);

        if (currentFlow == null) {
            // 이 HttpSecurity 인스턴스에 어떤 Flow가 매핑되었는지 알 수 없는 경우.
            // 또는 단일 SecurityFilterChain 구성 시 (PlatformConfig에 flows가 하나만 있거나 없는 경우)
            // 이 HttpSecurity가 그 유일한 대상이라고 가정하고 모든 Feature를 적용할 수도 있음.
            // 여기서는 FlowConfig가 공유되지 않으면 Feature 기반 Configurer는 추가하지 않음.
            log.warn("DefaultSecurityConfigurerProvider: AuthenticationFlowConfig not found in HttpSecurity sharedObjects for hash {}. " +
                            "Cannot determine flow-specific features. Only base configurers will be applied if called by orchestrator's flow loop.",
                    httpForScope.hashCode());
            return Collections.emptyList();
        }

        // 현재 Flow에 해당하는 AuthFeature들에 대한 Adapter 추가
        // FeatureRegistry.getAuthFeaturesFor는 이제 단일 AuthenticationFlowConfig를 받을 수 있도록 수정 필요 가능성
        // 또는 platformConfig.getFlows() 대신 currentFlow만 포함하는 리스트 전달
        List<AuthenticationFlowConfig> singleFlowList = Collections.singletonList(currentFlow);
        featureRegistry.getAuthFeaturesFor(singleFlowList)
                .forEach(feature -> {
                    // AuthFeatureConfigurerAdapter가 HttpSecurity를 필요로 한다면,
                    // 생성자에 httpForScope를 전달하거나, init/configure 시점에 FlowContext를 통해 전달.
                    // 현재 AuthFeatureConfigurerAdapter 생성자는 feature만 받음.
                    flowSpecificConfigurers.add(new AuthFeatureConfigurerAdapter(feature));
                    log.debug("DefaultSecurityConfigurerProvider: Added AuthFeatureConfigurerAdapter for feature '{}' to flow '{}'.",
                            feature.getId(), currentFlow.getTypeName());
                });

        // 현재 Flow에 해당하는 StateFeature들에 대한 Adapter 추가
        featureRegistry.getStateFeaturesFor(singleFlowList) // currentFlow의 StateConfig를 기반으로 결정
                .forEach(stateFeature -> {
                    // StateFeatureConfigurerAdapter는 PlatformContext를 받음
                    flowSpecificConfigurers.add(new StateFeatureConfigurerAdapter(stateFeature, platformContext));
                    log.debug("DefaultSecurityConfigurerProvider: Added StateFeatureConfigurerAdapter for feature '{}' to flow '{}'.",
                            stateFeature.getId(), currentFlow.getTypeName());
                });

        // ASEP의 경우: AsepConfigurer는 싱글톤 빈으로 getBaseConfigurers()에 이미 포함되어 있음.
        // 그 AsepConfigurer의 configure(FlowContext) 메소드 내에서
        // httpForScope.getSharedObject(XxxAsepAttributes.class)를 통해 커스텀 설정을 로드함.
        // 따라서 여기서 AsepConfigurer를 다시 추가할 필요는 없음.

        log.debug("DefaultSecurityConfigurerProvider: Providing {} flow-specific configurers for flow '{}'.",
                flowSpecificConfigurers.size(), currentFlow.getTypeName());
        return List.copyOf(flowSpecificConfigurers);
    }
}
