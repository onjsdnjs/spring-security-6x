package io.springsecurity.springsecurity6x.security.core.feature.auth.mfa;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.StateHandlerRegistry;
import io.springsecurity.springsecurity6x.security.filter.MfaOrchestrationFilter;
import io.springsecurity.springsecurity6x.security.filter.MfaStepFilterWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.util.Assert;

import java.util.List;

@Slf4j
public class MfaAuthenticationFeature implements AuthenticationFeature {

    private static final String ID = "mfa";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int getOrder() {
        // MFA 플로우는 다른 단일 인증 플로우보다 일반적으로 먼저 처리될 필요는 없음.
        // 각 SecurityFilterChain은 고유한 requestMatcher를 가지므로 순서는 덜 중요할 수 있으나,
        // 명시적으로 다른 단일 인증과 구분되는 order를 가질 수 있음.
        return 500; // 예시 order
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig stateConfig) throws Exception {
        // HttpSecurity에 공유된 핵심 MFA 객체들 가져오기
        ContextPersistence ctxPersistence = http.getSharedObject(ContextPersistence.class);
        StateMachineManager stateMachine = http.getSharedObject(StateMachineManager.class);
        StateHandlerRegistry stateHandlerRegistry = http.getSharedObject(StateHandlerRegistry.class);
        FeatureRegistry featureRegistry = http.getSharedObject(FeatureRegistry.class); // 실제로는 ApplicationContext 통해 접근

        Assert.notNull(ctxPersistence, "ContextPersistence not found in HttpSecurity shared objects for MFA flow.");
        Assert.notNull(stateMachine, "StateMachineManager not found for MFA flow.");
        Assert.notNull(stateHandlerRegistry, "StateHandlerRegistry not found for MFA flow.");
        Assert.notNull(featureRegistry, "FeatureRegistry not found for MFA flow.");

        // 1. MfaOrchestrationFilter 추가 (MFA 상태 관리 및 전이 담당)
        // 이 필터는 1차 인증 성공 후 또는 MFA API 호출 시 동작해야 함.
        // RequestMatcher는 MFA 관련 API 엔드포인트 (예: /api/mfa/**) 및 1차 인증 성공 후 리다이렉션 되는 경로 등을 포함해야 함.
        // PlatformSecurityConfig 에서 MFA 플로우의 loginProcessingUrl (예: /api/auth/login)에 대한 요청도 처리.
        MfaOrchestrationFilter mfaOrchestrationFilter = new MfaOrchestrationFilter(ctxPersistence, stateMachine);
        // MfaOrchestrationFilter는 UsernamePasswordAuthenticationFilter 같은 1차 인증 필터 *이후*에,
        // 하지만 실제 2차 factor 인증 필터들 *이전*에 위치하는 것이 적절할 수 있음.
        // 또는 1차 인증 성공 핸들러가 특정 attribute를 설정하면, 그 attribute를 보고 동작하도록 할 수도 있음.
        // 현재는 LogoutFilter 전에 추가 (일반적인 커스텀 필터 위치)
        http.addFilterBefore(mfaOrchestrationFilter, LogoutFilter.class);


        // 2. StepTransitionFilter (MfaState에 따른 MfaStateHandler 호출) - 현재는 MfaOrchestrationFilter가 이 역할 일부 수행 가능
        // StepTransitionFilter stepTransitionFilter = new StepTransitionFilter(ctxPersistence, stateHandlerRegistry);
        // http.addFilterBefore(stepTransitionFilter, MfaOrchestrationFilter.class); // Orchestration 보다 먼저 상태 처리

        // 3. MfaStepFilterWrapper (실제 Factor 인증 필터 호출)
        // 이 필터는 특정 Factor 인증 URL (예: /login/mfa-ott, /login/mfa-passkey) 요청 시 해당 Factor 필터를 호출
        MfaStepFilterWrapper mfaStepFilterWrapper = new MfaStepFilterWrapper(featureRegistry, ctxPersistence);
        http.addFilterBefore(mfaStepFilterWrapper, MfaOrchestrationFilter.class); // Orchestration 필터보다 먼저 특정 factor 처리 시도

        // 4. 각 AuthenticationStepConfig에 따라 해당 인증 방식(Feature)의 apply 호출
        // (주의: MfaAuthenticationFeature의 apply 내에서 다시 개별 Feature의 apply를 호출하는 것은 재귀적일 수 있으므로,
        //  MfaAuthenticationFeature는 필터 체인 구성에 집중하고, 실제 각 스텝의 필터 설정은
        //  SecurityPlatformInitializer 에서 AuthFeatureConfigurerAdapter를 통해 이루어지는 것이 현재 구조임.
        //  여기서는 MfaAuthenticationFeature가 MFA 흐름에 필요한 *공통 필터*들만 추가하고,
        //  개별 인증 스텝(1차 인증 포함)에 대한 필터는 해당 AuthenticationFeature의 apply에서 처리되도록 유도.
        //  즉, 이 apply 메서드는 MFA 흐름을 위한 전반적인 필터(MfaOrchestrationFilter 등)를 설정하고,
        //  실제 1차 인증 필터, OTT 필터, Passkey 필터 등은 각자의 Feature.apply()에서 추가됨.
        //  PlatformConfig.java 에서 MFA flow에 `.rest().ott().passkey()` 등으로 정의하면,
        //  SecurityPlatformInitializer가 각 AuthFeatureConfigurerAdapter를 통해 RestAuthenticationFeature,
        //  OttAuthenticationFeature, PasskeyAuthenticationFeature의 apply를 호출하여 필터를 구성함.
        //  따라서 MfaAuthenticationFeature.apply 에서는 MFA 전체 흐름을 관장하는 필터만 추가하는 것이 맞음.
        //  stepConfigs 리스트는 이 Feature가 아닌, SecurityPlatformInitializer 에서 루프를 돌며 각 Feature에 전달됨.

        // 예를 들어, 1차 인증 스텝 설정 (이 로직은 실제로는 RestAuthenticationFeature.apply 등에서 수행됨)
        if (steps != null && !steps.isEmpty()) {
            AuthenticationStepConfig firstStep = steps.getFirst();
            AuthenticationFeature primaryAuthFeature = featureRegistry.getAuthFeaturesFor(List.of(AuthenticationFlowConfig.builder(firstStep.getType()).stepConfigs(List.of(firstStep)).build())).stream().findFirst().orElse(null);
            // primaryAuthFeature.apply(http, List.of(firstStep), stateConfig); // 이렇게 직접 호출하지 않음. 어댑터가 처리.
        }

        log.info("MFA common filters (MfaOrchestrationFilter, MfaStepFilterWrapper) configured for HttpSecurity.");
    }
}

