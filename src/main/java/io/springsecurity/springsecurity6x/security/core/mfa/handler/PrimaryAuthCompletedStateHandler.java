package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils; // CollectionUtils 추가

import java.util.Set;

@Slf4j
public class PrimaryAuthCompletedStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        log.debug("[MFA Handler] PrimaryAuthCompleted: Current state: {}, Event: {}, Session ID: {}", ctx.getCurrentState(), event, ctx.getMfaSessionId());

//        if (event == MfaEvent.MFA_REQUIRED_CHECK_COMPLETED) {
        if (event == MfaEvent.ISSUE_TOKEN) {
            // FactorContext에 MFA 필요 여부(isMfaRequired)와 등록된 Factor 목록(getRegisteredMfaFactors),
            // 자동 시도 Factor(getPreferredAutoAttemptFactor)가 설정되어 있다고 가정합니다.
            // 이 정보는 MfaPolicyProvider 등을 통해 미리 FactorContext에 채워져야 합니다.
            if (ctx.isMfaRequired()) {
                AuthType autoAttemptFactor = ctx.getPreferredAutoAttemptFactor();
                Set<AuthType> registeredFactors = ctx.getRegisteredMfaFactors();

                if (autoAttemptFactor != null && !CollectionUtils.isEmpty(registeredFactors) && registeredFactors.contains(autoAttemptFactor)) {
                    log.info("[MFA Handler] MFA required. Auto-attempting factor: {}. Session ID: {}", autoAttemptFactor, ctx.getMfaSessionId());
                    ctx.setCurrentProcessingFactor(autoAttemptFactor);
                    // 자동 시도 Factor가 Passkey Conditional UI와 같은 즉각적인 상호작용을 요구한다면
                    // 바로 FACTOR_CHALLENGE_INITIATED로 갈 수도 있지만,
                    // 여기서는 AUTO_ATTEMPT_FACTOR_PENDING 상태를 거치도록 설계합니다.
                    return MfaState.AUTO_ATTEMPT_FACTOR_PENDING;
                } else if (!CollectionUtils.isEmpty(registeredFactors)) {
                    log.info("[MFA Handler] MFA required. No auto-attempt factor or not registered. User needs to select a factor. Session ID: {}", ctx.getMfaSessionId());
                    return MfaState.AWAITING_MFA_FACTOR_SELECTION;
                } else {
                    log.warn("[MFA Handler] MFA required for user '{}', but no MFA factors are registered. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
                    ctx.recordAttempt(null, false, "MFA required but no factors registered.");
                    return MfaState.MFA_FAILURE_TERMINAL; // MFA 설정 오류로 간주
                }
            } else {
                log.info("[MFA Handler] MFA not required for user '{}'. Proceeding to token issuance. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
                return MfaState.TOKEN_ISSUANCE_REQUIRED; // MFA 불필요 시
            }
        }
        log.warn("[MFA Handler] PrimaryAuthCompleted: Unsupported event {} in state {}. Session ID: {}", event, ctx.getCurrentState(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}

