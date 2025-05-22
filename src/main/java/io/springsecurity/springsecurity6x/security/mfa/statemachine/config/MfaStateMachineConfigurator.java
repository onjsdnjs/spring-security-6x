package io.springsecurity.springsecurity6x.security.mfa.statemachine.config;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaEventPayload;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.action.*; // Action 임포트
import io.springsecurity.springsecurity6x.security.mfa.statemachine.guard.AllRequiredFactorsAreCompletedGuard;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.guard.IsFactorAvailableGuard;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext; // Action/Guard 빈을 가져오기 위함
import org.springframework.stereotype.Component;

import java.util.*;

import static io.springsecurity.springsecurity6x.security.enums.AuthType.OTT;
import static io.springsecurity.springsecurity6x.security.enums.AuthType.PASSKEY;

/**
 * AuthenticationFlowConfig를 기반으로 MfaStateMachineDefinition을 구성합니다.
 * 또는 직접 스프링 상태 머신 설정을 제공합니다.
 * 이 클래스는 상태 머신 "정의"를 생성하는 역할을 합니다.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MfaStateMachineConfigurator {

    private final ApplicationContext applicationContext; // 빈으로 등록된 Action, Guard 가져오기

    public MfaStateMachineDefinition buildDefinition(AuthenticationFlowConfig mfaFlowConfig) {
        // mfaFlowConfig를 분석하여 상태, 이벤트, 전이 규칙을 동적으로 설정합니다.
        // 예시: 1차 인증 성공 후, mfaFlowConfig에 정의된 2차 요소들에 따라 전이 규칙 생성

        MfaStateMachineDefinition.Transition.TransitionBuilder tBuilder = MfaStateMachineDefinition.Transition.builder();
        List<MfaStateMachineDefinition.Transition> transitions = new ArrayList<>();

        // --- 공통 Action/Guard 빈 가져오기 (예시) ---
        // 실제로는 각 전이나 상태에 맞는 특정 Action/Guard를 주입받거나 찾아야 함.
        InitializeMfaSessionAction initAction = applicationContext.getBean(InitializeMfaSessionAction.class);
        AllRequiredFactorsAreCompletedGuard allCompletedGuard = applicationContext.getBean(AllRequiredFactorsAreCompletedGuard.class);
        FinalizeMfaSuccessAction finalSuccessAction = applicationContext.getBean(FinalizeMfaSuccessAction.class);
        RedirectToFactorSelectionAction selectUiAction = applicationContext.getBean(RedirectToFactorSelectionAction.class);
        IsFactorAvailableGuard factorAvailableGuard = applicationContext.getBean(IsFactorAvailableGuard.class); // 예시 Guard


        // 1. 초기 상태 -> 1차 인증 완료
        transitions.add(tBuilder
                .source(MfaState.START_MFA).target(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .event(MfaEvent.PRIMARY_AUTH_COMPLETED)
                .action(initAction)
                .build());

        // 2. 1차 인증 완료 후 -> 팩터 선택 또는 특정 팩터 챌린지
        // 이 부분은 MfaPolicyProvider의 로직을 벤치마킹하여 Guard와 Action으로 분리/구현
        transitions.add(tBuilder
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED).target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR) // MfaPolicy가 판단한 이벤트
                .action(selectUiAction) // 선택 UI로 안내하는 액션
                .build());

        // 각 StepConfig (2차 요소)에 대한 전이 규칙 동적 생성
        for (AuthenticationStepConfig step : mfaFlowConfig.getStepConfigs()) { // 1차 인증 step은 제외하고 2차 요소들만
            if (isPrimaryAuthStep(step, mfaFlowConfig)) continue; // 1차 인증 스텝은 이미 처리됨

            MfaState awaitingChallengeState;
            MfaEvent factorSelectedEvent;
            MfaEvent challengeIssuedEvent;
            MfaEvent credentialSubmittedEvent;
            MfaEvent verificationSuccessEvent;
            MfaEvent verificationFailureEvent;
            MfaAction initiateChallengeAction;
            MfaAction verifyCredentialAction;

            // AuthType에 따라 상태, 이벤트, 액션 매핑
            switch (step.getAuthType()) {
                case OTT:
                    awaitingChallengeState = MfaState.AWAITING_OTT_VERIFICATION;
                    factorSelectedEvent = MfaEvent.FACTOR_SELECTED_OTT;
                    challengeIssuedEvent = MfaEvent.OTT_CHALLENGE_ISSUED; // sendOtpAction 내부에서 발생시킬 수도 있음
                    credentialSubmittedEvent = MfaEvent.OTT_SUBMITTED;
                    verificationSuccessEvent = MfaEvent.OTT_VERIFIED;
                    verificationFailureEvent = MfaEvent.OTT_VERIFICATION_FAILED;
                    initiateChallengeAction = applicationContext.getBean("sendOtpAction", MfaAction.class); // 빈 이름으로 가져오기
                    verifyCredentialAction = applicationContext.getBean("verifyOtpAction", MfaAction.class);
                    break;
                case PASSKEY:
                    awaitingChallengeState = MfaState.AWAITING_PASSKEY_VERIFICATION;
                    factorSelectedEvent = MfaEvent.FACTOR_SELECTED_PASSKEY;
                    challengeIssuedEvent = MfaEvent.PASSKEY_CHALLENGE_ISSUED;
                    credentialSubmittedEvent = MfaEvent.PASSKEY_ASSERTION_SUBMITTED;
                    verificationSuccessEvent = MfaEvent.PASSKEY_VERIFIED;
                    verificationFailureEvent = MfaEvent.PASSKEY_VERIFICATION_FAILED;
                    initiateChallengeAction = applicationContext.getBean("generatePasskeyAssertionOptionsAction", MfaAction.class);
                    verifyCredentialAction = applicationContext.getBean("verifyPasskeyAssertionAction", MfaAction.class);
                    break;
                // TODO: 다른 AuthType에 대한 case 추가
                default:
                    log.warn("Unsupported AuthType {} for MFA step {} in MfaStateMachineConfigurator. Skipping.", step.getAuthType(), step.getStepId());
                    continue;
            }

            // AWAITING_FACTOR_SELECTION -> (팩터 선택) -> AWAITING_FACTOR_CHALLENGE_INITIATION (또는 바로 awaitingChallengeState)
            transitions.add(tBuilder
                    .source(MfaState.AWAITING_FACTOR_SELECTION).target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                    .event(factorSelectedEvent)
                    .guard(ctx -> factorAvailableGuard.evaluate(ctx.toBuilder().payload(MfaEventPayload.with("stepId", step.getStepId())).build())) // 해당 팩터 사용 가능 여부
                    .action(context -> { // 현재 stepId를 FactorContext에 설정하는 액션
                        context.getFactorContext().setCurrentStepId(step.getStepId());
                        context.getFactorContext().setCurrentProcessingFactor(step.getAuthType());
                        context.getFactorContext().setCurrentFactorOptions((AuthenticationProcessingOptions) step.getOptions().get("_options"));
                        // 그리고 initiateChallengeAction을 호출하거나, 다음 이벤트(CHALLENGE_INITIATED_SUCCESSFULLY)를 발생시키는 이벤트 발행
                    })
                    .build());

            // AWAITING_FACTOR_CHALLENGE_INITIATION -> (챌린지 시작) -> awaitingChallengeState
            transitions.add(tBuilder
                    .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                    .target(awaitingChallengeState)
                    .event(MfaEvent.CHALLENGE_INITIATED_SUCCESSFULLY) // initiateChallengeAction의 성공 결과
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId())) // 현재 처리중인 스텝인지 확인
                    // .action(해당 팩터의 UI 렌더링 액션 - MfaContinuationHandler가 처리)
                    .build());

            transitions.add(tBuilder // 챌린지 시작 액션 자체를 여기에 넣을 수도 있음
                    .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                    .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) // 새 상태: 사용자가 입력 중인 상태
                    .event(MfaEvent.CHALLENGE_INITIATED_SUCCESSFULLY) // 또는 다른 이벤트 (예: RENDER_FACTOR_UI)
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()))
                    .action(initiateChallengeAction) // initiateChallengeAction은 챌린지를 보내고, 성공 시 CHALLENGE_ISSUED 이벤트를 발생시키거나 다음 상태로 바로 감
                    .build());


            // awaitingChallengeState (또는 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) -> (사용자 제출) -> (검증)
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                    .target(MfaState.FACTOR_VERIFICATION_IN_PROGRESS) // 새 상태: 검증 진행 중
                    .event(credentialSubmittedEvent)
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()))
                    .action(verifyCredentialAction) // 이 액션 내부에서 성공/실패 이벤트를 상태 머신에 다시 보냄
                    .build());

            // (검증 진행 중) -> (검증 성공)
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.AWAITING_FACTOR_SELECTION) // 기본적으로 다음 팩터 선택으로. 모든 팩터 완료 시 다른 상태로 가는 전이가 우선 적용될 것임.
                    .event(verificationSuccessEvent)
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()) && !allCompletedGuard.evaluate(ctx))
                    .action(applicationContext.getBean(UpdateFactorContextOnFactorSuccessAction.class)) // 완료 기록
                    .action(selectUiAction) // 다음 UI로
                    .build());

            // (검증 진행 중) -> (모든 팩터 완료 시 성공)
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.ALL_FACTORS_COMPLETED)
                    .event(verificationSuccessEvent)
                    .guard(ctx -> step.getStepId().equals(ctx.getFactorContext().getCurrentStepId()) && allCompletedGuard.evaluate(ctx))
                    .action(applicationContext.getBean(UpdateFactorContextOnFactorSuccessAction.class)) // 완료 기록
                    .build());

            // (검증 진행 중) -> (검증 실패)
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) // 실패 시 다시 현재 팩터 입력 화면으로 (재시도 정책은 Guard로)
                    .event(verificationFailureEvent)
                    .guard(ctx -> { // 예: 재시도 가능 Guard
                        RetryPolicy retryPolicy = applicationContext.getBean(MfaPolicyProvider.class).getRetryPolicy(ctx.getFactorContext(), step);
                        return retryPolicy.canRetry(ctx.getFactorContext(), step.getStepId());
                    })
                    .action(context -> { /* 실패 메시지 설정 등의 액션 */})
                    .build());

            // (검증 진행 중) -> (검증 실패 및 재시도 불가 시 최종 실패)
            transitions.add(tBuilder
                    .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                    .target(MfaState.MFA_FAILED_TERMINAL)
                    .event(verificationFailureEvent)
                    .guard(ctx -> {
                        RetryPolicy retryPolicy = applicationContext.getBean(MfaPolicyProvider.class).getRetryPolicy(ctx.getFactorContext(), step);
                        return !retryPolicy.canRetry(ctx.getFactorContext(), step.getStepId());
                    })
                    .build());
        }

        // ALL_FACTORS_COMPLETED -> (토큰 발급 이벤트) -> MFA_SUCCESSFUL
        transitions.add(tBuilder
                .source(MfaState.ALL_FACTORS_COMPLETED).target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN) // 이 이벤트는 ALL_FACTORS_COMPLETED 상태 진입 액션에서 자동 발생시킬 수 있음
                // .action(finalSuccessAction) // MFA_SUCCESSFUL 상태 진입 액션으로 처리하는 것이 더 일반적
                .build());

        // 전역 취소
        for(MfaState sourceState : EnumSet.complementOf(EnumSet.of(MfaState.MFA_SUCCESSFUL, MfaState.MFA_FAILED_TERMINAL, MfaState.END_MFA))) {
            transitions.add(tBuilder
                    .source(sourceState).target(MfaState.MFA_CANCELLED)
                    .event(MfaEvent.USER_ABORTED_MFA)
                    // .action(취소 처리 액션)
                    .build());
        }
        // MFA_CANCELLED -> END_MFA (또는 다른 정리 상태)
        transitions.add(tBuilder
                .source(MfaState.MFA_CANCELLED).target(MfaState.END_MFA)
                .build());


        return MfaStateMachineDefinition.builder()
                .initialState(MfaState.START_MFA)
                .states(EnumSet.allOf(MfaState.class))
                .endState(MfaState.END_MFA)
                .transitions(transitions) // .transition(t1).transition(t2)... 형태로도 가능
                .onStateEntry(MfaState.MFA_SUCCESSFUL, finalSuccessAction) // 예시: 상태 진입 액션
                .onStateEntry(MfaState.MFA_FAILED_TERMINAL, applicationContext.getBean(HandleMfaFailureAction.class))
                .build();
    }

    private boolean isPrimaryAuthStep(AuthenticationStepConfig stepConfig, AuthenticationFlowConfig flowConfig) {
        // AuthenticationFlowConfig에 1차 인증 스텝을 식별하는 방법이 필요함.
        // 예를 들어, flowConfig.getPrimaryAuthenticationOptions().getStepId() 와 stepConfig.getStepId()를 비교
        PrimaryAuthenticationOptions primaryOptions = flowConfig.getPrimaryAuthenticationOptions(); // 이 메소드가 있다고 가정
        return primaryOptions != null && Objects.equals(primaryOptions.getPrimaryAuthStepId(), stepConfig.getStepId());
    }
}
