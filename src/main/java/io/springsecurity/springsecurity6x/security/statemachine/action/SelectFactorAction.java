// SelectFactorAction.java - 전체 수정 코드
package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
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

    public SelectFactorAction(FactorContextStateAdapter factorContextAdapter) {
        super(factorContextAdapter);
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();

        // 선택된 팩터 타입 추출 - 메시지 헤더 우선
        String selectedFactor = (String) context.getMessageHeader("selectedFactor");
        if (selectedFactor == null) {
            selectedFactor = (String) context.getExtendedState().getVariables().get("selectedFactor");
        }

        // FactorContext의 attribute에서도 확인 (Handler에서 설정한 경우)
        if (selectedFactor == null) {
            selectedFactor = (String) factorContext.getAttribute("selectedFactor");
        }

        if (selectedFactor == null) {
            throw new IllegalStateException("No factor selected for session: " + sessionId);
        }

        log.info("Factor {} selected for session: {}", selectedFactor, sessionId);

        // AuthType 으로 변환
        AuthType authType;
        try {
            authType = AuthType.valueOf(selectedFactor.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid factor type: " + selectedFactor);
        }

        // 선택된 팩터가 사용자가 등록한 팩터인지 검증
        if (!factorContext.getRegisteredMfaFactors().contains(authType)) {
            throw new IllegalStateException("Selected factor " + authType +
                    " is not registered for user: " + factorContext.getUsername());
        }

        // 현재 처리 중인 팩터 설정
        factorContext.setCurrentProcessingFactor(authType);

        // 선택 시간 기록
        factorContext.setAttribute("factorSelectedAt", System.currentTimeMillis());

        // 팩터별 추가 설정 - 시스템 설정이나 사용자 설정에서 가져옴
        switch (authType) {
            case OTT:
                // OTT 전송 방법 설정 - 하드코딩 제거
                String ottDeliveryMethod = determineOttDeliveryMethod(context, factorContext);
                factorContext.setAttribute("ottDeliveryMethod", ottDeliveryMethod);
                log.debug("OTT delivery method set to: {} for session: {}",
                        ottDeliveryMethod, sessionId);
                break;

            case PASSKEY:
                // Passkey 타입 설정 - 하드코딩 제거
                String passkeyType = determinePasskeyType(context, factorContext);
                factorContext.setAttribute("passkeyType", passkeyType);
                log.debug("Passkey type set to: {} for session: {}",
                        passkeyType, sessionId);
                break;

            default:
                log.debug("No additional settings for factor: {}", authType);
        }

        // 상태 머신 변수 업데이트
        context.getExtendedState().getVariables().put("currentSelectedFactor", authType.name());
        context.getExtendedState().getVariables().put("factorSelectionTime", System.currentTimeMillis());

        log.info("Factor selection completed for session: {}, factor: {}", sessionId, authType);
    }

    /**
     * OTT 전송 방법 결정
     * 우선순위: 1) 요청 파라미터 2) 사용자 설정 3) 시스템 기본값
     */
    private String determineOttDeliveryMethod(StateContext<MfaState, MfaEvent> context,
                                              FactorContext factorContext) {
        // 1. 요청에서 전달된 방법 확인
        String requestedMethod = (String) context.getMessageHeader("ottDeliveryMethod");
        if (requestedMethod != null) {
            return validateOttDeliveryMethod(requestedMethod);
        }

        // 2. 사용자 설정 확인
        String userPreference = (String) factorContext.getAttribute("userOttPreference");
        if (userPreference != null) {
            return validateOttDeliveryMethod(userPreference);
        }

        // 3. 시스템 설정 확인
        String systemDefault = (String) context.getExtendedState().getVariables()
                .getOrDefault("systemOttDeliveryMethod", "SMS");

        return validateOttDeliveryMethod(systemDefault);
    }

    /**
     * Passkey 타입 결정
     */
    private String determinePasskeyType(StateContext<MfaState, MfaEvent> context,
                                        FactorContext factorContext) {
        // 1. 요청에서 전달된 타입
        String requestedType = (String) context.getMessageHeader("passkeyType");
        if (requestedType != null) {
            return validatePasskeyType(requestedType);
        }

        // 2. 디바이스 정보 기반 결정
        String userAgent = (String) factorContext.getAttribute("userAgent");
        if (userAgent != null) {
            if (userAgent.contains("Mobile")) {
                return "MOBILE";
            } else if (userAgent.contains("Windows") || userAgent.contains("Mac")) {
                return "PLATFORM";
            }
        }

        // 3. 기본값
        return "PLATFORM";
    }

    /**
     * OTT 전송 방법 유효성 검증
     */
    private String validateOttDeliveryMethod(String method) {
        if (method == null) {
            return "EMAIL";
        }

        String upperMethod = method.toUpperCase();
        return switch (upperMethod) {
            case "SMS", "EMAIL", "VOICE", "PUSH" -> upperMethod;
            default -> {
                log.warn("Invalid OTT delivery method: {}, defaulting to SMS", method);
                yield "EMAIL";
            }
        };
    }

    /**
     * Passkey 타입 유효성 검증
     */
    private String validatePasskeyType(String type) {
        if (type == null) {
            return "PLATFORM";
        }

        String upperType = type.toUpperCase();
        switch (upperType) {
            case "PLATFORM":
            case "CROSS_PLATFORM":
            case "MOBILE":
            case "HYBRID":
                return upperType;
            default:
                log.warn("Invalid passkey type: {}, defaulting to PLATFORM", type);
                return "PLATFORM";
        }
    }

    @Override
    protected void validatePreconditions(StateContext<MfaState, MfaEvent> context,
                                         FactorContext factorContext) throws Exception {
        // 등록된 팩터가 있는지 확인
        if (factorContext.getRegisteredMfaFactors() == null ||
                factorContext.getRegisteredMfaFactors().isEmpty()) {
            throw new IllegalStateException("No MFA factors registered for user: " +
                    factorContext.getUsername());
        }

        // 현재 상태가 팩터 선택 대기 상태인지 확인
        if (factorContext.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("Factor selection attempted in invalid state: {} for session: {}",
                    factorContext.getCurrentState(), factorContext.getMfaSessionId());
        }
    }
}