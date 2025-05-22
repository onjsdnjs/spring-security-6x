package io.springsecurity.springsecurity6x.security.mfa.statemachine.config;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
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
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;

// static import 제거 (AuthType.OTT, AuthType.PASSKEY 직접 사용 권장 또는 enum 클래스명으로 접근)
// import static io.springsecurity.springsecurity6x.security.enums.AuthType.OTT;
// import static io.springsecurity.springsecurity6x.security.enums.AuthType.PASSKEY;

/**
 * AuthenticationFlowConfig를 기반으로 MfaStateMachineDefinition을 구성합니다.
 * 이 클래스는 상태 머신 "정의"를 생성하는 역할을 합니다.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MfaStateMachineConfigurator {

    private final ApplicationContext applicationContext;

    public MfaStateMachineDefinition buildDefinition(AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null for building MfaStateMachineDefinition");
        log.debug("Building MfaStateMachineDefinition for flow: {}", mfaFlowConfig.getTypeName());

        MfaStateMachineDefinition.Transition.TransitionBuilder tBuilder = MfaStateMachineDefinition.Transition.builder();
        List<MfaStateMachineDefinition.Transition> transitions = new ArrayList<>();

        // --- Action 및 Guard 빈 가져오기 (빈 이름 또는 클래스 타입으로) ---
        InitializeMfaSessionAction initAction = applicationContext.getBean("initializeMfaSessionAction", InitializeMfaSessionAction.class);
        AllRequiredFactorsAreCompletedGuard allCompletedGuard = applicationContext.getBean("allRequiredFactorsAreCompletedGuard", AllRequiredFactorsAreCompletedGuard.class);
        FinalizeMfaSuccessAction finalSuccessAction = applicationContext.getBean("finalizeMfaSuccessAction", FinalizeMfaSuccessAction.class);
        RedirectToFactorSelectionAction selectUiAction = applicationContext.getBean("redirectToFactorSelectionAction", RedirectToFactorSelectionAction.class);
        IsFactorAvailableGuard factorAvailableGuard = applicationContext.getBean("isFactorAvailableGuard", IsFactorAvailableGuard.class);
        // 추가적으로 필요한 Action/Guard 빈들 (예시)
        MfaAction sendOtpAction = applicationContext.getBean("sendOtpAction", MfaAction.class); // 실제 빈 이름 확인 필요
        MfaAction verifyOtpAction = applicationContext.getBean("verifyOtpAction", MfaAction.class);
        MfaAction generatePasskeyOptionsAction = applicationContext.getBean("generatePasskeyAssertionOptionsAction", MfaAction.class);
        MfaAction verifyPasskeyAssertionAction = applicationContext.getBean("verifyPasskeyAssertionAction", MfaAction.class);
        MfaAction updateFactorContextOnSuccessAction = applicationContext.getBean("updateFactorContextOnFactorSuccessAction", MfaAction.class);
        MfaAction handleMfaFailureAction = applicationContext.getBean("handleMfaFailureAction", MfaAction.class); // 이 빈도 구현 필요


        // 1. 초기 상태 -> 1차 인증 완료
        transitions.add(tBuilder
                .source(MfaState.START_MFA).target(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL)
                .event(MfaEvent.PRIMARY_AUTH_COMPLETED)
                .action(initAction) // InitializeMfaSessionAction
                .build());

        // 2. 1차 인증 완료 후 -> (정책 결과에 따라) 팩터 선택 또는 특정 팩터 챌린지
        transitions.add(tBuilder
                .source(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL).target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_POLICY_EVALUATED_SELECT_FACTOR)
                .action(selectUiAction) // RedirectToFactorSelectionAction
                .build());

        // 1차 인증 완료 후 -> (정책 결과에 따라) 특정 팩터 챌린지 즉시 시작 (예: OTT)
        // 이 전이는 MfaPolicyProvider가 "하나의 팩터만 등록 & 필수" 등의 조건일 때 발생시키는 이벤트를 따름
        transitions.add(tBuilder
                .source(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL).target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.MFA_POLICY_EVALUATED_INITIATE_FACTOR)
                // .guard(ctx -> ctx.getPayload().get("factorToInitiate", AuthType.class) == AuthType.OTT) // payload로 어떤 팩터인지 받아야 함
                .action(context -> { // 현재 선택된(또는 정책에 의해 결정된) 팩터 정보를 FactorContext에 설정하는 액션
                    AuthType factorToInitiate = context.getPayload() != null ? context.getPayload().get("factorToInitiate", AuthType.class) : null;
                    AuthenticationStepConfig stepToInitiate = findStepConfigForAuthType(mfaFlowConfig, factorToInitiate);
                    if (stepToInitiate != null) {
                        context.getFactorContext().setCurrentStepId(stepToInitiate.getStepId());
                        context.getFactorContext().setCurrentProcessingFactor(stepToInitiate.getAuthType());
                        context.getFactorContext().setCurrentFactorOptions((AuthenticationProcessingOptions) stepToInitiate.getOptions().get("_options"));
                        log.debug("MFA_POLICY_EVALUATED_INITIATE_FACTOR: Set current processing factor to {} (StepId: {})",
                                factorToInitiate, stepToInitiate.getStepId());
                    } else {
                        log.warn("MFA_POLICY_EVALUATED_INITIATE_FACTOR: Could not find step config for AuthType: {}", factorToInitiate);
                        // 오류 처리 또는 다른 상태로 전이 필요
                    }
                })
                .build());

        // 1차 인증 완료 후 -> (정책 결과에 따라) MFA 생략하고 바로 최종 성공
        transitions.add(tBuilder
                .source(MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL).target(MfaState.ALL_FACTORS_COMPLETED) // 또는 MFA_SUCCESSFUL
                .event(MfaEvent.MFA_POLICY_ALLOWS_BYPASS)
                // .action(MFA 생략 관련 로그 기록 액션 등)
                .build());


        // 각 StepConfig (2차 요소)에 대한 전이 규칙 동적 생성
        // getSteps()가 List<AuthenticationStepConfig>를 반환한다고 가정
        for (AuthenticationStepConfig step : mfaFlowConfig.getStepConfigs()) {
//            if (isPrimaryAuthStep(step, mfaFlowConfig)) continue; // 1차 인증 스텝은 별도 처리

            MfaState awaitingChallengeState;
            MfaEvent factorSelectedEvent;
            // MfaEvent challengeIssuedEvent; // 액션 내부에서 다음 이벤트 발생 또는 상태 직접 변경
            MfaEvent credentialSubmittedEvent;
            MfaEvent verificationSuccessEvent;
            MfaEvent verificationFailureEvent;
            MfaAction selectedFactorAction; // 팩터 선택 시 현재 처리 팩터 정보 설정
            MfaAction initiateChallengeAction = null; // 각 타입에 맞는 챌린지 액션
            MfaAction verifyCredentialAction = null;  // 각 타입에 맞는 검증 액션

            switch (step.getAuthType()) { // AuthenticationStepConfig에 getAuthType()이 있다고 가정
                case OTT:
                    awaitingChallengeState = MfaState.AWAITING_OTT_VERIFICATION; // Configurator에서 직접 사용하지 않음
                    factorSelectedEvent = MfaEvent.FACTOR_SELECTED_OTT;
                    // challengeIssuedEvent = MfaEvent.CHALLENGE_ISSUED_SUCCESSFULLY;
                    credentialSubmittedEvent = MfaEvent.SUBMIT_OTT_CODE;
                    verificationSuccessEvent = MfaEvent.FACTOR_VERIFIED_SUCCESS; // payload로 OTT 타입 명시
                    verificationFailureEvent = MfaEvent.FACTOR_VERIFICATION_FAILED; // payload로 OTT 타입 명시
                    initiateChallengeAction = sendOtpAction;
                    verifyCredentialAction = verifyOtpAction;
                    break;
                case PASSKEY:
                    awaitingChallengeState = MfaState.AWAITING_PASSKEY_VERIFICATION; // Configurator에서 직접 사용하지 않음
                    factorSelectedEvent = MfaEvent.FACTOR_SELECTED_PASSKEY;
                    // challengeIssuedEvent = MfaEvent.CHALLENGE_ISSUED_SUCCESSFULLY;
                    credentialSubmittedEvent = MfaEvent.SUBMIT_PASSKEY_ASSERTION;
                    verificationSuccessEvent = MfaEvent.FACTOR_VERIFIED_SUCCESS; // payload로 Passkey 타입 명시
                    verificationFailureEvent = MfaEvent.FACTOR_VERIFICATION_FAILED; // payload로 Passkey 타입 명시
                    initiateChallengeAction = generatePasskeyOptionsAction;
                    verifyCredentialAction = verifyPasskeyAssertionAction;
                    break;
                default:
                    log.warn("Unsupported AuthType {} for MFA step {} in MfaStateMachineConfigurator. Skipping this step's transitions.",
                            step.getAuthType(), step.getStepId());
                    continue;
            }

            // 공통 액션: 사용자가 팩터를 선택했을 때, FactorContext에 현재 처리할 stepId와 AuthType, Options 설정
            selectedFactorAction = context -> {
                log.debug("Factor {} (StepId: {}) selected by user {}.", step.getAuthType(), step.getStepId(), context.getFactorContext().getUsername());
                context.getFactorContext().setCurrentStepId(step.getStepId());
                context.getFactorContext().setCurrentProcessingFactor(step.getAuthType());
                context.getFactorContext().setCurrentFactorOptions((AuthenticationProcessingOptions) step.getOptions().get("_options"));
            };


            // AWAITING_FACTOR_SELECTION -> (팩터 선택) -> AWAITING_FACTOR_CHALLENGE_INITIATION
            transitions.add(tBuilder
                    .source(MfaState.AWAITING_FACTOR_SELECTION)
                    .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                    .event(factorSelectedEvent)
                    .guard(ctx -> factorAvailableGuard.evaluate(
                            ctx.toBuilder().payload(MfaEventPayload.with("stepId", step.getStepId())).build()
                    ))
                    .action(selectedFactorAction) // 선택된 팩터 정보 FactorContext에 설정
                    .build());

            // AWAITING_FACTOR_CHALLENGE_INITIATION -> (챌린지 시작 액션) -> FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION
            if (initiateChallengeAction != null) {
                transitions.add(tBuilder
                        .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                        .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                        .event(MfaEvent.INITIATE_CHALLENGE) // 이 이벤트는 selectedFactorAction 직후 또는 MfaContinuationHandler가 발생시킬 수 있음
                        .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId())) // 현재 처리 스텝인지 확인
                        .action(initiateChallengeAction) // 예: OTP 발송, Passkey 옵션 생성. 이 액션 성공 시 내부적으로 CHALLENGE_ISSUED_SUCCESSFULLY 발생시킬 수도.
                        .build());
            }

            // FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION 상태에서 챌린지 성공 후 다음 상태로 (선택적, initiateChallengeAction이 직접 상태 변경 안 할 경우)
            transitions.add(tBuilder
                    .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) // 또는 initiateChallengeAction 이전의 상태
                    .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                    .event(MfaEvent.CHALLENGE_ISSUED_SUCCESSFULLY) // initiateChallengeAction이 성공적으로 챌린지를 제시했을 때 발생시키는 이벤트
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()))
                    // .action(UI 업데이트 또는 사용자에게 안내하는 액션)
                    .build());


            // FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION -> (사용자 제출) -> FACTOR_VERIFICATION_IN_PROGRESS
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                    .target(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .event(credentialSubmittedEvent) // 예: SUBMIT_OTT_CODE, SUBMIT_PASSKEY_ASSERTION
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()))
                    .action(verifyCredentialAction) // 이 액션은 내부적으로 FACTOR_VERIFIED_SUCCESS 또는 FACTOR_VERIFICATION_FAILED 이벤트를 발생시킴
                    .build());

            // FACTOR_VERIFICATION_IN_PROGRESS -> (검증 성공) -> AWAITING_FACTOR_SELECTION (다음 팩터 선택)
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.AWAITING_FACTOR_SELECTION)
                    .event(verificationSuccessEvent) // FACTOR_VERIFIED_SUCCESS (payload로 AuthType 구분)
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()) && !allCompletedGuard.evaluate(ctx)) // 모든 필수 팩터 미완료
                    .action(updateFactorContextOnSuccessAction) // FactorContext에 현재 팩터 완료 기록
                    .action(selectUiAction) // 다음 팩터 선택 UI로
                    .build());

            // FACTOR_VERIFICATION_IN_PROGRESS -> (검증 성공 및 모든 팩터 완료) -> ALL_FACTORS_COMPLETED
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.ALL_FACTORS_COMPLETED)
                    .event(verificationSuccessEvent) // FACTOR_VERIFIED_SUCCESS
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()) && allCompletedGuard.evaluate(ctx)) // 모든 필수 팩터 완료
                    .action(updateFactorContextOnSuccessAction) // FactorContext에 현재 팩터 완료 기록
                    .build());

            // FACTOR_VERIFICATION_IN_PROGRESS -> (검증 실패, 재시도 가능) -> FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) // 현재 팩터 재시도
                    .event(verificationFailureEvent) // FACTOR_VERIFICATION_FAILED
                    .guard(ctx -> {
                        if (!step.getStepId().equals(ctx.getFactorContext().getCurrentStepId())) return false;
                        RetryPolicy retryPolicy = applicationContext.getBean(MfaPolicyProvider.class).getRetryPolicy(ctx.getFactorContext(), step);
                        return retryPolicy.canRetry(ctx.getFactorContext(), step.getStepId());
                    })
                    .action(context -> {
                        log.warn("Factor verification failed for step '{}', user '{}'. Retrying.", step.getStepId(), context.getFactorContext().getUsername());
                        // 실패 메시지 설정 등의 액션
                    })
                    .build());

            // FACTOR_VERIFICATION_IN_PROGRESS -> (검증 실패, 재시도 불가) -> MFA_FAILED_TERMINAL
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.MFA_FAILED_TERMINAL)
                    .event(verificationFailureEvent) // FACTOR_VERIFICATION_FAILED
                    .guard(ctx -> {
                        if (!step.getStepId().equals(ctx.getFactorContext().getCurrentStepId())) return false;
                        RetryPolicy retryPolicy = applicationContext.getBean(MfaPolicyProvider.class).getRetryPolicy(ctx.getFactorContext(), step);
                        return !retryPolicy.canRetry(ctx.getFactorContext(), step.getStepId());
                    })
                    .build());
        }


        // ALL_FACTORS_COMPLETED -> (최종 토큰 발급 이벤트) -> MFA_SUCCESSFUL
        transitions.add(tBuilder
                .source(MfaState.ALL_FACTORS_COMPLETED).target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED) // ALL_FACTORS_COMPLETED 상태 진입 액션에서 이 이벤트 발생시킬 수 있음
                // 또는 MfaPolicyProvider.checkAllFactorsCompleted가 직접 이 이벤트 발생
                // .action(finalSuccessAction) // MFA_SUCCESSFUL 상태의 진입 액션으로 처리하는 것이 더 일반적
                .build());

        // 모든 활성 상태에서 사용자 취소 처리 -> MFA_CANCELLED
        // EnumSet.allOf(MfaState.class)에서 터미널 상태들을 제외하고 루프
        EnumSet<MfaState> nonTerminalStates = EnumSet.complementOf(
                EnumSet.of(MfaState.MFA_SUCCESSFUL, MfaState.MFA_FAILED_TERMINAL, MfaState.END_MFA, MfaState.MFA_CANCELLED)
        );
        for (MfaState sourceState : nonTerminalStates) {
            transitions.add(tBuilder
                    .source(sourceState).target(MfaState.MFA_CANCELLED)
                    .event(MfaEvent.USER_ABORTED_MFA)
                    // .action(사용자 취소 관련 정리 액션)
                    .build());
        }

        // MFA_CANCELLED -> END_MFA
        transitions.add(tBuilder
                .source(MfaState.MFA_CANCELLED).target(MfaState.END_MFA)
                // .action(최종 정리 액션)
                .build());

        // MFA_FAILED_TERMINAL 상태에 대한 onEntry 액션은 MfaStateMachineDefinition.builder()에서 설정
        // MFA_SUCCESSFUL 상태에 대한 onEntry 액션도 MfaStateMachineDefinition.builder()에서 설정


        return MfaStateMachineDefinition.builder()
                .initialState(MfaState.START_MFA)
                .states(EnumSet.allOf(MfaState.class)) // 모든 MfaState enum 값을 상태로 등록
                .endState(MfaState.END_MFA) // 명시적 종료 상태
                .transitions(transitions)
                .onStateEntry(MfaState.MFA_SUCCESSFUL, finalSuccessAction) // MFA_SUCCESSFUL 상태 진입 시 finalSuccessAction 실행
                .onStateEntry(MfaState.MFA_FAILED_TERMINAL, handleMfaFailureAction) // MFA_FAILED_TERMINAL 상태 진입 시 handleMfaFailureAction 실행
                .build();
    }

/*
    private boolean isPrimaryAuthStep(AuthenticationStepConfig stepConfig, AuthenticationFlowConfig flowConfig) {
        if (stepConfig == null || flowConfig == null) return false;
        PrimaryAuthenticationOptions primaryOptions = flowConfig.getPrimaryAuthenticationOptions();
        return primaryOptions != null &&
                primaryOptions.getPrimaryAuthStepConfig() != null && // PrimaryAuthStepConfig가 설정되어 있는지 확인
                Objects.equals(primaryOptions.getPrimaryAuthStepConfig().getStepId(), stepConfig.getStepId());
    }
*/

    // MfaFlowConfig 에서 AuthType에 해당하는 StepConfig를 찾는 헬퍼 (필요시 사용)
    private AuthenticationStepConfig findStepConfigForAuthType(AuthenticationFlowConfig flowConfig, AuthType authType) {
        if (flowConfig == null || authType == null || CollectionUtils.isEmpty(flowConfig.getStepConfigs())) {
            return null;
        }
        return flowConfig.getStepConfigs().stream()
                .filter(s -> authType.equals(s.getAuthType()))
                .findFirst()
                .orElse(null);
    }
}