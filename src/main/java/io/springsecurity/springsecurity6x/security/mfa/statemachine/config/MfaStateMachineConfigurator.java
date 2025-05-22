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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
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
@Slf4j
public class MfaStateMachineConfigurator {

    private final InitializeMfaSessionAction initializeMfaSessionAction;
    private final AllRequiredFactorsAreCompletedGuard allRequiredFactorsAreCompletedGuard;
    private final FinalizeMfaSuccessAction finalizeMfaSuccessAction;
    private final RedirectToFactorSelectionAction redirectToFactorSelectionAction;
    private final IsFactorAvailableGuard isFactorAvailableGuard;
    private final MfaAction sendOtpAction;
    private final MfaAction verifyOtpAction;
    private final MfaAction generatePasskeyAssertionOptionsAction;
    private final MfaAction verifyPasskeyAssertionAction;
    private final MfaAction updateFactorContextOnFactorSuccessAction;
    private final MfaAction handleMfaFailureAction;
    private final MfaPolicyProvider mfaPolicyProvider; // RetryPolicy 가져오기 위해 필요

    // 생성자 주입을 통해 ApplicationContext에 대한 직접적인 의존성 제거
    public MfaStateMachineConfigurator(
            InitializeMfaSessionAction initializeMfaSessionAction,
            AllRequiredFactorsAreCompletedGuard allRequiredFactorsAreCompletedGuard,
            FinalizeMfaSuccessAction finalizeMfaSuccessAction,
            RedirectToFactorSelectionAction redirectToFactorSelectionAction,
            IsFactorAvailableGuard isFactorAvailableGuard,
            @Qualifier("sendOtpAction") MfaAction sendOtpAction, // 빈 이름이 클래스명과 다를 경우 @Qualifier 사용
            @Qualifier("verifyOtpAction") MfaAction verifyOtpAction,
            @Qualifier("generatePasskeyAssertionOptionsAction") MfaAction generatePasskeyAssertionOptionsAction,
            @Qualifier("verifyPasskeyAssertionAction") MfaAction verifyPasskeyAssertionAction,
            @Qualifier("updateFactorContextOnFactorSuccessAction") MfaAction updateFactorContextOnSuccessAction,
            @Qualifier("handleMfaFailureAction") MfaAction handleMfaFailureAction,
            MfaPolicyProvider mfaPolicyProvider) {
        this.initializeMfaSessionAction = initializeMfaSessionAction;
        this.allRequiredFactorsAreCompletedGuard = allRequiredFactorsAreCompletedGuard;
        this.finalizeMfaSuccessAction = finalizeMfaSuccessAction;
        this.redirectToFactorSelectionAction = redirectToFactorSelectionAction;
        this.isFactorAvailableGuard = isFactorAvailableGuard;
        this.sendOtpAction = sendOtpAction;
        this.verifyOtpAction = verifyOtpAction;
        this.generatePasskeyAssertionOptionsAction = generatePasskeyAssertionOptionsAction;
        this.verifyPasskeyAssertionAction = verifyPasskeyAssertionAction;
        this.updateFactorContextOnFactorSuccessAction = updateFactorContextOnSuccessAction;
        this.handleMfaFailureAction = handleMfaFailureAction;
        this.mfaPolicyProvider = mfaPolicyProvider;
    }

    public MfaStateMachineDefinition buildDefinition(AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null for building MfaStateMachineDefinition");
        log.debug("Building MfaStateMachineDefinition for flow: {}", mfaFlowConfig.getTypeName());

        List<MfaStateMachineDefinition.Transition> transitions = new ArrayList<>();

        // Action 및 Guard는 이미 생성자를 통해 주입받았으므로 바로 사용
        // InitializeMfaSessionAction initAction = this.initializeMfaSessionAction; 와 같이 사용

        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.START_MFA).target(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL)
                .event(MfaEvent.PRIMARY_AUTH_COMPLETED)
                .action(this.initializeMfaSessionAction)
                .build());

        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL).target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_POLICY_EVALUATED_SELECT_FACTOR)
                .action(this.redirectToFactorSelectionAction)
                .build());

        transitions.add(MfaStateMachineDefinition.Transition.builder()
                .source(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL).target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.MFA_POLICY_EVALUATED_INITIATE_FACTOR)
                .action(context -> {
                    MfaEventPayload payload = context.getPayload(); // MfaProcessingContext에 getPayload() 필요
                    AuthType factorToInitiate = payload != null ? payload.get("factorToInitiate", AuthType.class) : null; // MfaEventPayload에 get() 필요
                    AuthenticationStepConfig stepToInitiate = findStepConfigForAuthType(context.getFlowConfig(), factorToInitiate); // MfaProcessingContext에 getFlowConfig() 필요
                    FactorContext factorCtx = context.getFactorContext(); // MfaProcessingContext에 getFactorContext() 필요
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

        if (mfaFlowConfig.getStepConfigs() != null) { // AuthenticationFlowConfig에 getSteps() 필요
            for (AuthenticationStepConfig step : mfaFlowConfig.getStepConfigs()) {
                if (isPrimaryAuthStep(step, mfaFlowConfig)) {
                    log.trace("Skipping primary auth step '{}' for secondary factor transition building.", step.getStepId());
                    continue;
                }

                MfaEvent factorSelectedEvent;
                MfaEvent credentialSubmittedEvent;
                MfaAction currentInitiateChallengeAction = null;
                MfaAction currentVerifyCredentialAction = null;

                switch (step.getAuthType()) { // AuthenticationStepConfig에 getAuthType() 필요
                    case OTT:
                        factorSelectedEvent = MfaEvent.FACTOR_SELECTED_OTT;
                        credentialSubmittedEvent = MfaEvent.SUBMIT_OTT_CODE;
                        currentInitiateChallengeAction = this.sendOtpAction;
                        currentVerifyCredentialAction = this.verifyOtpAction;
                        break;
                    case PASSKEY:
                        factorSelectedEvent = MfaEvent.FACTOR_SELECTED_PASSKEY;
                        credentialSubmittedEvent = MfaEvent.SUBMIT_PASSKEY_ASSERTION;
                        currentInitiateChallengeAction = this.generatePasskeyAssertionOptionsAction;
                        currentVerifyCredentialAction = this.verifyPasskeyAssertionAction;
                        break;
                    default:
                        log.warn("Unsupported AuthType {} for MFA step {} in MfaStateMachineConfigurator. Skipping this step's transitions.",
                                step.getAuthType(), step.getStepId());
                        continue;
                }

                MfaAction selectedFactorContextSetupAction = context -> {
                    FactorContext factorCtx = context.getFactorContext();
                    if (factorCtx != null) {
                        log.debug("Factor {} (StepId: {}) selected by user {}. Setting in FactorContext.",
                                step.getAuthType(), step.getStepId(), factorCtx.getUsername());
                        factorCtx.setCurrentStepId(step.getStepId());
                        factorCtx.setCurrentProcessingFactor(step.getAuthType());
                        factorCtx.setCurrentFactorOptions((AuthenticationProcessingOptions) step.getOptions().get("_options")); // AuthenticationStepConfig에 getOptions() 필요
                    } else {
                        log.error("Cannot setup selected factor context: FactorContext is null. Event: {}, StepId: {}", context.getEvent(), step.getStepId());
                    }
                };

                transitions.add(MfaStateMachineDefinition.Transition.builder()
                        .source(MfaState.AWAITING_FACTOR_SELECTION)
                        .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                        .event(factorSelectedEvent)
                        .guard(ctx -> this.isFactorAvailableGuard.evaluate(
                                // MfaProcessingContext.toBuilder() 와 MfaEventPayload.with() 가 필요
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
                            MfaEventPayload payload = ctx.getPayload();
                            FactorContext factorCtx = ctx.getFactorContext();
                            return factorCtx != null &&
                                    step.getStepId().equals(factorCtx.getCurrentStepId()) &&
                                    (payload == null || step.getAuthType().equals(payload.get("verifiedFactorType", AuthType.class))) &&
                                    !this.allRequiredFactorsAreCompletedGuard.evaluate(ctx);
                        })
                        .action(this.updateFactorContextOnFactorSuccessAction)
                        .action(this.redirectToFactorSelectionAction)
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
                                    this.allRequiredFactorsAreCompletedGuard.evaluate(ctx);
                        })
                        .action(this.updateFactorContextOnFactorSuccessAction)
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
                            RetryPolicy retryPolicy = this.mfaPolicyProvider.getRetryPolicy(factorCtx, step);
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
                            RetryPolicy retryPolicy = this.mfaPolicyProvider.getRetryPolicy(factorCtx, step);
                            return !retryPolicy.canRetry(factorCtx, step.getStepId());
                        })
                        .build());
            }
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
                .onStateEntry(MfaState.MFA_SUCCESSFUL, this.finalizeMfaSuccessAction)
                .onStateEntry(MfaState.MFA_FAILED_TERMINAL, this.handleMfaFailureAction)
                .build();
    }

    /**
     * 주어진 AuthenticationStepConfig가 MFA 플로우의 1차 인증 단계인지 확인합니다.
     * AuthenticationFlowConfig의 PrimaryAuthenticationOptions에 저장된 (또는 설정된)
     * 1차 인증 stepId와 비교하여 판단합니다.
     */
    private boolean isPrimaryAuthStep(AuthenticationStepConfig stepConfigToTest, AuthenticationFlowConfig flowConfig) {
        if (stepConfigToTest == null || flowConfig == null) {
            log.trace("isPrimaryAuthStep: stepConfigToTest or flowConfig is null, returning false.");
            return false;
        }
        PrimaryAuthenticationOptions primaryOptions = flowConfig.getPrimaryAuthenticationOptions();
        if (primaryOptions == null) {
            log.trace("isPrimaryAuthStep: PrimaryAuthenticationOptions not found in flowConfig '{}'. Assuming step '{}' is not primary.",
                    flowConfig.getTypeName(), stepConfigToTest.getStepId());
            return false;
        }

        // PrimaryAuthenticationOptions에 1차 인증으로 사용된 StepConfig의 ID가 저장되어 있다고 가정.
        // 이 값은 MfaDslConfigurerImpl에서 primaryAuthentication 설정 시 PrimaryAuthenticationOptions에 채워져야 함.
        String primaryAuthStepId = primaryOptions.getPrimaryAuthStepId(); // 이 메소드가 PrimaryAuthenticationOptions에 있어야 함

        if (!StringUtils.hasText(primaryAuthStepId)) {
            // 이 경우는 PrimaryAuthDslConfigurerImpl 또는 MfaDslConfigurerImpl에서
            // 1차 인증 stepId를 PrimaryAuthenticationOptions에 제대로 설정하지 않았음을 의미.
            log.warn("isPrimaryAuthStep: Primary authentication stepId is NOT DEFINED in PrimaryAuthenticationOptions for flow '{}'. " +
                            "Cannot reliably determine if step '{}' is primary. THIS IS LIKELY A DSL CONFIGURATION ISSUE. Assuming false.",
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
        // AuthenticationFlowConfig에 getSteps() 또는 getStepConfigs()가 있다고 가정
        if (flowConfig == null || authType == null || CollectionUtils.isEmpty(flowConfig.getStepConfigs())) {
            return null;
        }
        return flowConfig.getStepConfigs().stream()
                .filter(s -> s != null && authType.equals(s.getAuthType())) // AuthenticationStepConfig에 getAuthType()이 있다고 가정
                .findFirst()
                .orElse(null);
    }
}