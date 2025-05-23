package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * MFA 팩터 선택 액션
 */
@Slf4j
@Component
public class SelectFactorAction extends AbstractMfaStateAction {

    public SelectFactorAction(FactorContextStateAdapter factorContextAdapter,
                              StateContextHelper stateContextHelper) {
        super(factorContextAdapter, stateContextHelper);
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();

        // 선택된 팩터 타입 추출
        String selectedFactor = (String) context.getMessageHeader("selectedFactor");
        if (selectedFactor == null) {
            selectedFactor = (String) context.getExtendedState().getVariables().get("selectedFactor");
        }

        if (selectedFactor == null) {
            throw new IllegalStateException("No factor selected for session: " + sessionId);
        }

        log.info("Factor {} selected for session: {}", selectedFactor, sessionId);

        // AuthType으로 변환
        AuthType authType;
        try {
            authType = AuthType.valueOf(selectedFactor.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid factor type: " + selectedFactor);
        }

        // 현재 처리 중인 팩터 설정
        factorContext.setCurrentProcessingFactor(authType);

        // 선택 시간 기록
        factorContext.setAttribute("factorSelectedAt", System.currentTimeMillis());

        // 팩터별 추가 설정
        switch (authType) {
            case OTT:
                factorContext.setAttribute("ottDeliveryMethod", "SMS"); // 기본값
                break;
            case PASSKEY:
                factorContext.setAttribute("passkeyType", "PLATFORM"); // 기본값
                break;
            default:
                log.debug("No additional settings for factor: {}", authType);
        }

        // 상태 업데이트
        factorContext.changeState(MfaState.FACTOR_SELECTED);

        log.info("Factor selection completed for session: {}", sessionId);
    }
}