package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
//@RequiredArgsConstructor // MfaPolicyProvider 주입을 위해
public class PrimaryAuthCompletedStateHandler implements MfaStateHandler {

//    private final MfaPolicyProvider mfaPolicyProvider; // MfaPolicyProvider 주입

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        log.debug("[MFA StateHandler] PrimaryAuthCompleted: Current state: {}, Event: {}, User: {}, Session ID: {}",
                ctx.getCurrentState(), event, ctx.getUsername(), ctx.getMfaSessionId());

        // 이 상태에서는 1차 인증 성공 후 MFA 정책 평가 결과를 반영하는 이벤트를 기대할 수 있습니다.
        // 예를 들어 MfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep 호출 후,
        // 그 결과에 따라 MfaContinuationFilter 또는 성공 핸들러가 적절한 이벤트를 발생시킵니다.

        if (event == MfaEvent.MFA_NOT_REQUIRED) {
            log.info("MFA not required for user '{}'. Proceeding to all factors completed. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
            ctx.setMfaRequiredAsPerPolicy(false); // 명시적으로 MFA 불필요 설정
            return MfaState.ALL_FACTORS_COMPLETED; // MFA 불필요 시 바로 모든 요소 완료 상태로 (토큰 발급 전 단계)
        } else if (event == MfaEvent.MFA_REQUIRED_SELECT_FACTOR) {
            // MfaPolicyProvider가 사용자가 Factor를 선택해야 한다고 결정한 경우
            log.info("MFA required for user '{}', user needs to select a factor. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
            ctx.setMfaRequiredAsPerPolicy(true);
            return MfaState.AWAITING_FACTOR_SELECTION;
        } else if (event == MfaEvent.MFA_REQUIRED_INITIATE_CHALLENGE) {
            // MfaPolicyProvider가 특정 Factor로 바로 챌린지를 시작해야 한다고 결정한 경우
            // (이때 FactorContext.currentProcessingFactor는 MfaPolicyProvider가 설정해야 함)
            AuthType initialFactor = ctx.getCurrentProcessingFactor();
            if (initialFactor == null) {
                log.error("MFA_REQUIRED_INITIATE_CHALLENGE event received, but no initial factor set in FactorContext for user '{}'. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
                return MfaState.MFA_SYSTEM_ERROR; // 또는 AWAITING_FACTOR_SELECTION으로 fallback
            }
            log.info("MFA required for user '{}', initiating challenge for factor: {}. Session ID: {}", ctx.getUsername(), initialFactor, ctx.getMfaSessionId());
            ctx.setMfaRequiredAsPerPolicy(true);
            return MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION;
        }
        // 제공된 MfaEvent.java 에는 AUTO_ATTEMPT_POSSIBLE 이벤트가 있으나,
        // 현재 MfaState.java 에는 AUTO_ATTEMPT_FACTOR_PENDING 상태가 없습니다.
        // 만약 자동 시도 로직이 필요하다면 MfaState에 해당 상태 추가 후 아래 로직 사용.
        /*
        else if (event == MfaEvent.AUTO_ATTEMPT_POSSIBLE) {
            AuthType autoFactor = ctx.getPreferredAutoAttemptFactor(); // MfaPolicyProvider가 설정
            if (autoFactor != null && ctx.getRegisteredMfaFactors().contains(autoFactor)) {
                log.info("MFA required for user '{}'. Auto-attempting factor: {}. Session ID: {}", ctx.getUsername(), autoFactor, ctx.getMfaSessionId());
                ctx.setMfaRequiredAsPerPolicy(true);
                ctx.setCurrentProcessingFactor(autoFactor);
                // return MfaState.AUTO_ATTEMPT_FACTOR_PENDING; // 해당 상태가 MfaState.java에 정의되어야 함
                return MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION; // 임시로 일반 챌린지 시작으로
            } else {
                 log.warn("AUTO_ATTEMPT_POSSIBLE event but no preferred/registered auto factor for user '{}'. Falling back to factor selection. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
                 ctx.setMfaRequiredAsPerPolicy(true);
                 return MfaState.AWAITING_FACTOR_SELECTION;
            }
        }
        */

        // 기존 코드의 MfaEvent.ISSUE_TOKEN 처리 로직은 MfaPolicyProvider의 평가 결과에 따라 분기되도록 수정.
        // MfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep에서
        // ctx.isMfaRequiredAsPerPolicy() 와 ctx.getCurrentProcessingFactor() 등을 설정하는 책임을 가짐.
        // 이 핸들러는 그 결과를 바탕으로 다음 상태를 결정.

        log.warn("PrimaryAuthCompletedStateHandler: Unsupported event {} in state {}. User: {}, Session ID: {}",
                event, ctx.getCurrentState(), ctx.getUsername(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}