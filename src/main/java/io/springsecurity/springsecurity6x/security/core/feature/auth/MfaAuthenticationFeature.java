package io.springsecurity.springsecurity6x.security.core.feature.auth;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.filter.MfaOrchestrationFilter;
import io.springsecurity.springsecurity6x.security.filter.MfaStepFilterWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.logout.LogoutFilter; // 정확한 위치로 LogoutFilter import
import org.springframework.util.Assert;

import java.util.List;
import java.util.Objects;

public class MfaAuthenticationFeature implements AuthenticationFeature {

    private static final Logger log = LoggerFactory.getLogger(MfaAuthenticationFeature.class);
    private static final String ID = "mfa";
    private ApplicationContext applicationContext;

    public MfaAuthenticationFeature() {}

    public MfaAuthenticationFeature(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for MfaAuthenticationFeature");
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int getOrder() {
        // MFA 공통 필터는 다른 개별 인증 필터들보다 먼저 또는 특정 위치에 적용될 수 있도록 order 조정
        return 10; // 예시: 다른 인증 Feature(100단위)들 보다 먼저 실행되도록
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> allStepsInCurrentFlow, StateConfig stateConfig) throws Exception {
        // 이 apply 메서드는 현재 HttpSecurity가 "mfa" 타입의 AuthenticationFlowConfig에 대한 것일 때 호출됨.
        AuthenticationFlowConfig currentFlow = http.getSharedObject(AuthenticationFlowConfig.class);

        // 이 Feature는 "mfa" 타입의 flow에만 적용되어야 함.
        // FeatureRegistry.getAuthFeaturesFor에서 "mfa" flow일 때 이 Feature를 반환하도록 했으므로,
        // 여기서 다시 flow type을 체크하는 것은 중복일 수 있으나, 안전장치로 둘 수 있음.
        if (currentFlow == null || !ID.equalsIgnoreCase(currentFlow.getTypeName())) {
            // AbstractAuthenticationFeature.apply에서 자신의 ID와 step.getType()을 비교하므로,
            // MfaAuthenticationFeature는 step type이 "mfa"인 경우에만 이 로직이 실행되도록 설계.
            // 만약 MfaAuthenticationFeature가 flow type "mfa" 전체에 대한 설정이라면,
            // AbstractAuthenticationFeature의 myRelevantStepConfig 필터링 로직을 타지 않도록 해야 함.
            // -> 이전 답변에서 MfaAuthenticationFeature가 AbstractAuthenticationFeature를 상속하지 않도록 변경했으므로,
            //    이 apply는 MfaAuthenticationFeature의 고유한 apply가 됨.
            log.trace("MfaAuthenticationFeature.apply() called, but current flow is not 'mfa' or FlowConfig not shared. Skipping MFA common filter setup.");
            return;
        }

        log.info("MfaAuthenticationFeature: Applying MFA common filters for flow '{}'.", currentFlow.getTypeName());

        ContextPersistence ctxPersistence = http.getSharedObject(ContextPersistence.class);
        StateMachineManager stateMachine = http.getSharedObject(StateMachineManager.class);
        FeatureRegistry featureRegistry = applicationContext.getBean(FeatureRegistry.class);

        Assert.notNull(ctxPersistence, "ContextPersistence not found for MFA flow.");
        Assert.notNull(stateMachine, "StateMachineManager not found for MFA flow."); // 이 시점에는 이미 공유되어 있어야 함
        Assert.notNull(featureRegistry, "FeatureRegistry bean not found.");

        // 1. MFA 흐름 제어 공통 필터 추가
        // MfaOrchestrationFilter의 RequestMatcher는 해당 MFA 플로우 내의 특정 API 경로들을 포함해야 함.
        // SecurityConfig 에서 HttpSecurity 객체에 requestMatcher()를 통해 이 MFA FilterChain이 적용될 경로를 지정.
        // 따라서 MfaOrchestrationFilter는 해당 FilterChain 내에서 모든 요청에 대해 동작하게 됨 (내부에서 다시 requestMatcher로 거름).
        MfaOrchestrationFilter mfaOrchestrationFilter = new MfaOrchestrationFilter(ctxPersistence, stateMachine);
        http.addFilterBefore(mfaOrchestrationFilter, LogoutFilter.class); // 예시 위치

        MfaStepFilterWrapper mfaStepFilterWrapper = new MfaStepFilterWrapper(featureRegistry, ctxPersistence);
        http.addFilterBefore(mfaStepFilterWrapper, MfaOrchestrationFilter.class); // Orchestration 필터보다 먼저 특정 factor 처리 시도

        log.debug("MFA common filters (MfaOrchestrationFilter, MfaStepFilterWrapper) added for MFA flow.");

        // 1차 인증 및 각 2차 인증 Factor에 대한 구체적인 필터 설정은
        // 이 HttpSecurity 객체에 대해 이어서 호출될 다른 개별 AuthenticationFeature들의 apply 메서드에서 담당함.
        // (예: RestAuthenticationFeature.apply(), OttAuthenticationFeature.apply() 등)
        // 그들은 AbstractAuthenticationFeature.apply()의 로직에 따라 자신과 관련된 stepConfig를 찾아 설정을 적용할 것임.
    }
}

