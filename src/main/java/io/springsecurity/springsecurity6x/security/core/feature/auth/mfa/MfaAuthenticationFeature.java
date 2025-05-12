package io.springsecurity.springsecurity6x.security.core.feature.auth.mfa;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.mfa.ChallengeRouter;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.StateHandlerRegistry;
import io.springsecurity.springsecurity6x.security.filter.MfaOrchestrationFilter;
import io.springsecurity.springsecurity6x.security.filter.MfaStepFilterWrapper;
import io.springsecurity.springsecurity6x.security.filter.StepTransitionFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.ExceptionTranslationFilter;

import java.util.List;

public class MfaAuthenticationFeature implements AuthenticationFeature {

    private static final String ID = "mfa";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int getOrder() {
        return 500;
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> stepConfigs, StateConfig stateConfig) throws Exception {

        // HttpSecurity에 공유된 오브젝트에서 의존성 꺼내기
        ContextPersistence ctxPersistence = http.getSharedObject(ContextPersistence.class);
        StateMachineManager stateMachine   = http.getSharedObject(StateMachineManager.class);
        StateHandlerRegistry registry       = http.getSharedObject(StateHandlerRegistry.class);
        FeatureRegistry      featureRegistry= http.getSharedObject(FeatureRegistry.class);
        ChallengeRouter      router         = http.getSharedObject(ChallengeRouter.class);

        // 1) Orchestration Entry Point Filter
        MfaOrchestrationFilter mfaFilter = new MfaOrchestrationFilter(ctxPersistence, stateMachine, registry, router);
        http.addFilterBefore(mfaFilter, ExceptionTranslationFilter.class);

        // 2) State Transition Filter
        StepTransitionFilter stepFilter = new StepTransitionFilter(ctxPersistence, stateMachine);
        http.addFilterAfter(stepFilter, MfaOrchestrationFilter.class);

        // 3) Step Filter Wrapper (인증 필터 호출)
        MfaStepFilterWrapper wrapper = new MfaStepFilterWrapper(featureRegistry, ctxPersistence);
        http.addFilterAfter(wrapper, StepTransitionFilter.class);
    }
}

