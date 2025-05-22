package io.springsecurity.springsecurity6x.security.mfa.statemachine.config;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaEventPayload;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.action.FinalizeMfaSuccessAction;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.action.InitializeMfaSessionAction;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.action.MfaAction;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.action.RedirectToFactorSelectionAction;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.guard.AllRequiredFactorsAreCompletedGuard;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.guard.IsFactorAvailableGuard;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;

@Component
@RequiredArgsConstructor
@Slf4j
public class MfaStateMachineConfigurator {

    private final ApplicationContext applicationContext;

    public MfaStateMachineDefinition buildDefinition(AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null for building MfaStateMachineDefinition");
        log.debug("Building MfaStateMachineDefinition for flow: {}", mfaFlowConfig.getTypeName());

        List<MfaStateMachineDefinition.Transition> transitions = new ArrayList<>();

        // Action 및 Guard 빈 가져오기
        InitializeMfaSessionAction initAction = applicationContext.getBean("initializeMfaSessionAction", InitializeMfaSessionAction.class);
        AllRequiredFactorsAreCompletedGuard allCompletedGuard = applicationContext.getBean("allRequiredFactorsAreCompletedGuard", AllRequiredFactorsAreCompletedGuard.class);
        FinalizeMfaSuccessAction finalSuccessAction = applicationContext.getBean("finalizeMfaSuccessAction", FinalizeMfaSuccessAction.class);
        RedirectToFactorSelectionAction selectUiAction = applicationContext.getBean("redirectToFactorSelectionAction", RedirectToFactorSelectionAction.class);
        IsFactorAvailableGuard factorAvailableGuard = applicationContext.getBean("isFactorAvailableGuard", IsFactorAvailableGuard.class);
        MfaAction sendOtpAction = applicationContext.getBean("sendOtpAction", MfaAction.class);
        MfaAction verifyOtpAction = applicationContext.getBean("verifyOtpAction", MfaAction.class);
        MfaAction generatePasskeyOptionsAction = applicationContext.getBean("generatePasskeyAssertionOptionsAction", MfaAction.class);
        MfaAction verifyPasskeyAssertionAction = applicationContext.getBean("verifyPasskeyAssertionAction", MfaAction.class);
        MfaAction updateFactorContextOnSuccessAction = applicationContext.getBean("updateFactorContextOnFactorSuccessAction", MfaAction.class);
        MfaAction handleMfaFailureAction = applicationContext.getBean("handleMfaFailureAction", MfaAction.class);


        // 각 Transition.builder()를 새로 호출하여 빌더 상태가 공유되지 않도록 함
        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.START_MFA).target(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL)
                .event(MfaEvent.PRIMARY_AUTH_COMPLETED)
                .action(initAction)
                .build());

        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL).target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_POLICY_EVALUATED_SELECT_FACTOR)
                .action(selectUiAction)
                .build());

        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL).target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.MFA_POLICY_EVALUATED_INITIATE_FACTOR)
                .action(context -> {
                    // MfaProcessingContext에 getFactorContext(), getPayload(), getFlowConfig()가 있다고 가정
                    // MfaEventPayload에 get(String, Class)가 있다고 가정
                    MfaEventPayload payload = context.getPayload(); // MfaProcessingContext에 getPayload()가 있어야 함
                    AuthType factorToInitiate = payload != null ? payload.get("factorToInitiate", AuthType.class) : null;
                    AuthenticationStepConfig stepToInitiate = findStepConfigForAuthType(context.getFlowConfig(), factorToInitiate);
                    FactorContext factorCtx = context.getFactorContext(); // MfaProcessingContext에 getFactorContext()가 있어야 함
                    if (stepToInitiate != null && factorCtx != null) {
                        factorCtx.setCurrentStepId(stepToInitiate.getStepId());
                        factorCtx.setCurrentProcessingFactor(stepToInitiate.getAuthType());
                        factorCtx.setCurrentFactorOptions((AuthenticationProcessingOptions) stepToInitiate.getOptions().get("_options"));
                        log.debug("MFA_POLICY_EVALUATED_INITIATE_FACTOR: Set current processing factor to {} (StepId: {})",
                                factorToInitiate, stepToInitiate.getStepId());
                    } else {
                        log.warn("MFA_POLICY_EVALUATED_INITIATE_FACTOR: Could not find step config for AuthType: {} or FactorContext/Payload is null.", factorToInitiate);
                    }
                })
                .build());

        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL).target(MfaState.ALL_FACTORS_COMPLETED)
                .event(MfaEvent.MFA_POLICY_ALLOWS_BYPASS)
                .build());

        // AuthenticationFlowConfig에 getSteps()가 있다고 가정
        for (AuthenticationStepConfig step : mfaFlowConfig.getStepConfigs()) {
            if (isPrimaryAuthStep(step, mfaFlowConfig)) { // 이 메소드는 아래에 수정된 버전 사용
                log.trace("Skipping primary auth step '{}' for secondary factor transition building.", step.getStepId());
                continue;
            }

            MfaEvent factorSelectedEvent;
            MfaEvent credentialSubmittedEvent;
            MfaAction currentInitiateChallengeAction = null;
            MfaAction currentVerifyCredentialAction = null;

            // AuthenticationStepConfig에 getAuthType()이 있다고 가정
            switch (step.getAuthType()) {
                case OTT:
                    factorSelectedEvent = MfaEvent.FACTOR_SELECTED_OTT;
                    credentialSubmittedEvent = MfaEvent.SUBMIT_OTT_CODE;
                    currentInitiateChallengeAction = sendOtpAction;
                    currentVerifyCredentialAction = verifyOtpAction;
                    break;
                case PASSKEY:
                    factorSelectedEvent = MfaEvent.FACTOR_SELECTED_PASSKEY;
                    credentialSubmittedEvent = MfaEvent.SUBMIT_PASSKEY_ASSERTION;
                    currentInitiateChallengeAction = generatePasskeyOptionsAction;
                    currentVerifyCredentialAction = verifyPasskeyAssertionAction;
                    break;
                default:
                    log.warn("Unsupported AuthType {} for MFA step {} in MfaStateMachineConfigurator. Skipping this step's transitions.",
                            step.getAuthType(), step.getStepId());
                    continue;
            }

            MfaAction selectedFactorContextSetupAction = context -> {
                FactorContext factorCtx = context.getFactorContext(); // MfaProcessingContext에 getFactorContext()가 있어야 함
                if (factorCtx != null) {
                    log.debug("Factor {} (StepId: {}) selected by user {}. Setting in FactorContext.",
                            step.getAuthType(), step.getStepId(), factorCtx.getUsername());
                    factorCtx.setCurrentStepId(step.getStepId());
                    factorCtx.setCurrentProcessingFactor(step.getAuthType());
                    factorCtx.setCurrentFactorOptions((AuthenticationProcessingOptions) step.getOptions().get("_options")); // AuthenticationStepConfig에 getOptions()가 있어야 함
                } else {
                    log.error("Cannot setup selected factor context: FactorContext is null. Event: {}, StepId: {}", context.getEvent(), step.getStepId());
                }
            };

            transitions.add(MfaStateMachineDefinition.Transition.builder()
                    .source(MfaState.AWAITING_FACTOR_SELECTION)
                    .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                    .event(factorSelectedEvent)
                    .guard(ctx -> factorAvailableGuard.evaluate(
                            // MfaProcessingContext.toBuilder()와 MfaEventPayload.with()가 있다고 가정
                            ctx.toBuilder().payload(MfaEventPayload.with("stepId", step.getStepId())).build()
                    ))
                    .action(selectedFactorContextSetupAction)
                    .build());

            if (currentInitiateChallengeAction != null) {
                transitions.add(MfaStateMachineDefinition.Transition.builder()
                        .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                        .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                        .event(MfaEvent.INITIATE_CHALLENGE)
                        .guard(ctx -> ctx.getFactorContext() != null && step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()))
                        .action(currentInitiateChallengeAction)
                        .build());
            }

            transitions.add(MfaStateMachineDefinition.Transition.builder()
                    .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                    .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                    .event(MfaEvent.CHALLENGE_ISSUED_SUCCESSFULLY)
                    .guard(ctx -> ctx.getFactorContext() != null && step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()))
                    .build());

            if (currentVerifyCredentialAction != null) {
                transitions.add(MfaStateMachineDefinition.Transition.builder()
                        .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                        .target(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                        .event(credentialSubmittedEvent)
                        .guard(ctx -> ctx.getFactorContext() != null && step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()))
                        .action(currentVerifyCredentialAction)
                        .build());
            }

            transitions.add(MfaStateMachineDefinition.Transition.builder()
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.AWAITING_FACTOR_SELECTION)
                    .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                    .guard(ctx -> {
                        // MfaProcessingContext에 getFactorContext(), getPayload() 존재 가정
                        // MfaEventPayload에 get(String, Class) 존재 가정
                        MfaEventPayload payload = ctx.getPayload();
                        FactorContext factorCtx = ctx.getFactorContext();
                        return factorCtx != null &&
                                step.getStepId().equals(factorCtx.getCurrentStepId()) &&
                                (payload == null || step.getAuthType().equals(payload.get("verifiedFactorType", AuthType.class))) &&
                                !allCompletedGuard.evaluate(ctx);
                    })
                    .action(updateFactorContextOnSuccessAction)
                    .action(selectUiAction)
                    .build());

            transitions.add(MfaStateMachineDefinition.Transition.builder()
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.ALL_FACTORS_COMPLETED)
                    .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                    .guard(ctx -> {
                        MfaEventPayload payload = ctx.getPayload();
                        FactorContext factorCtx = ctx.getFactorContext();
                        return factorCtx != null &&
                                step.getStepId().equals(factorCtx.getCurrentStepId()) &&
                                (payload == null || step.getAuthType().equals(payload.get("verifiedFactorType", AuthType.class))) &&
                                allCompletedGuard.evaluate(ctx);
                    })
                    .action(updateFactorContextOnSuccessAction)
                    .build());

            transitions.add(MfaStateMachineDefinition.Transition.builder()
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                    .event(MfaEvent.FACTOR_VERIFICATION_FAILED)
                    .guard(ctx -> {
                        MfaEventPayload payload = ctx.getPayload();
                        FactorContext factorCtx = ctx.getFactorContext();
                        if (factorCtx == null ||
                                !step.getStepId().equals(factorCtx.getCurrentStepId()) ||
                                (payload != null && !step.getAuthType().equals(payload.get("failedFactorType", AuthType.class)))) {
                            return false;
                        }
                        // AuthenticationStepConfig에 getOptions()가 있고, 반환된 Options 객체로 RetryPolicy를 가져올 수 있다고 가정
                        // 또는 MfaPolicyProvider가 stepId를 기반으로 RetryPolicy를 반환한다고 가정
                        RetryPolicy retryPolicy = applicationContext.getBean(MfaPolicyProvider.class).getRetryPolicy(factorCtx, step);
                        return retryPolicy.canRetry(factorCtx, step.getStepId());
                    })
                    .action(context -> {
                        FactorContext factorCtx = context.getFactorContext();
                        log.warn("Factor verification failed for step '{}', user '{}'. Retrying.",
                                step.getStepId(),
                                factorCtx != null ? factorCtx.getUsername() : "UNKNOWN_USER");
                    })
                    .build());

            transitions.add(MfaStateMachineDefinition.Transition.builder()
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.MFA_FAILED_TERMINAL)
                    .event(MfaEvent.FACTOR_VERIFICATION_FAILED)
                    .guard(ctx -> {
                        MfaEventPayload payload = ctx.getPayload();
                        FactorContext factorCtx = ctx.getFactorContext();
                        if (factorCtx == null ||
                                !step.getStepId().equals(factorCtx.getCurrentStepId()) ||
                                (payload != null && !step.getAuthType().equals(payload.get("failedFactorType", AuthType.class)))) {
                            return false;
                        }
                        RetryPolicy retryPolicy = applicationContext.getBean(MfaPolicyProvider.class).getRetryPolicy(factorCtx, step);
                        return !retryPolicy.canRetry(factorCtx, step.getStepId());
                    })
                    .build());
        }

        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.ALL_FACTORS_COMPLETED).target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .build());

        EnumSet<MfaState> nonTerminalStates = EnumSet.complementOf(
                EnumSet.of(MfaState.MFA_SUCCESSFUL, MfaState.MFA_FAILED_TERMINAL, MfaState.END_MFA, MfaState.MFA_CANCELLED)
        );
        for (MfaState sourceState : nonTerminalStates) {
            transitions.add(MfaStateMachineDefinition.Transition.builder()
                    .source(sourceState).target(MfaState.MFA_CANCELLED)
                    .event(MfaEvent.USER_ABORTED_MFA)
                    .build());
        }

        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.MFA_CANCELLED).target(MfaState.END_MFA)
                .build());

        return MfaStateMachineDefinition.builder()
                .initialState(MfaState.START_MFA)
                .states(EnumSet.allOf(MfaState.class))
                .endState(MfaState.END_MFA)
                .transitions(transitions)
                .onStateEntry(MfaState.MFA_SUCCESSFUL, finalSuccessAction)
                .onStateEntry(MfaState.MFA_FAILED_TERMINAL, handleMfaFailureAction)
                .build();
    }

    /**
     * 주어진 AuthenticationStepConfig가 MFA 플로우의 1차 인증 단계인지 확인합니다.
     * AuthenticationFlowConfig의 PrimaryAuthenticationOptions에 저장된 1차 인증 AuthType과
     * 해당 AuthType을 가진 첫 번째 Step의 stepId를 비교합니다.
     * 또는 PrimaryAuthenticationOptions에 1차 인증 stepId가 직접 저장되어 있다면 그것을 사용합니다.
     */
    private boolean isPrimaryAuthStep(AuthenticationStepConfig stepConfigToTest, AuthenticationFlowConfig flowConfig) {
        if (stepConfigToTest == null || flowConfig == null) {
            log.trace("isPrimaryAuthStep: stepConfigToTest or flowConfig is null, returning false.");
            return false;
        }
        PrimaryAuthenticationOptions primaryOptions = flowConfig.getPrimaryAuthenticationOptions(); // AuthenticationFlowConfig에 이 getter가 있어야 함
        if (primaryOptions == null) {
            log.trace("isPrimaryAuthStep: PrimaryAuthenticationOptions not found in flowConfig '{}'. Assuming step '{}' is not primary.",
                    flowConfig.getTypeName(), stepConfigToTest.getStepId());
            return false;
        }

        // 해결책: PrimaryAuthenticationOptions에 저장된 primaryAuthStepId를 직접 사용
        String primaryAuthStepId = primaryOptions.getPrimaryAuthStepId(); // 이 메소드가 PrimaryAuthenticationOptions에 있어야 함

        if (!StringUtils.hasText(primaryAuthStepId)) {
            // 이 경우는 PrimaryAuthDslConfigurerImpl에서 stepId를 PrimaryAuthenticationOptions에 제대로 설정하지 않았음을 의미.
            // 또는 PrimaryAuthenticationOptions 자체에 해당 정보가 없는 초기 상태일 수 있음.
            // 좀 더 견고하게 하려면, primaryOptions.getPrimaryAuthType()을 사용하고,
            // flowConfig.getSteps()에서 해당 AuthType을 가진 첫 번째 step의 ID와 비교할 수 있음.
            // 하지만 이는 1차 인증 타입이 steps 리스트에서 유일하거나 첫 번째라는 가정이 필요.
            log.warn("isPrimaryAuthStep: Primary authentication stepId is not defined or accessible in PrimaryAuthenticationOptions for flow '{}'. " +
                            "Cannot reliably determine if step '{}' is primary. Assuming false.",
                    flowConfig.getTypeName(), stepConfigToTest.getStepId());
            return false;
        }

        boolean isPrimary = Objects.equals(primaryAuthStepId, stepConfigToTest.getStepId());
        log.trace("isPrimaryAuthStep: Comparing current stepConfig.getStepId() ('{}') with stored primaryAuthStepId ('{}') for flow '{}'. Result: {}",
                stepConfigToTest.getStepId(), primaryAuthStepId, flowConfig.getTypeName(), isPrimary);
        return isPrimary;
    }

    @Nullable
    private AuthenticationStepConfig findStepConfigForAuthType(AuthenticationFlowConfig flowConfig, @Nullable AuthType authType) {
        // AuthenticationFlowConfig에 getSteps()가 있다고 가정
        if (flowConfig == null || authType == null || CollectionUtils.isEmpty(flowConfig.getStepConfigs())) {
            return null;
        }
        return flowConfig.getStepConfigs().stream()
                .filter(s -> s != null && authType.equals(s.getAuthType())) // AuthenticationStepConfig에 getAuthType()이 있다고 가정
                .findFirst()
                .orElse(null);
    }
}