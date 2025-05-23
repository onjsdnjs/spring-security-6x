package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class CompleteMfaAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        log.info("Completing MFA flow for user: {} in session: {}",
                factorContext.getUsername(), factorContext.getMfaSessionId());

        // MFA 완료 처리
        // JWT 토큰 발급 준비
        // 감사 로그 기록 등

        context.getExtendedState().getVariables().put("mfaCompletedAt", System.currentTimeMillis());

        // completedFactors가 문자열 Set인 경우
        if (factorContext.getCompletedFactors() != null && !factorContext.getCompletedFactors().isEmpty()) {
            String completedFactorsStr = String.join(",", (CharSequence) factorContext.getCompletedFactors());
            context.getExtendedState().getVariables().put("completedFactors", completedFactorsStr);
        }
    }

    @Override
    public String getActionName() {
        return "CompleteMfaAction";
    }
}