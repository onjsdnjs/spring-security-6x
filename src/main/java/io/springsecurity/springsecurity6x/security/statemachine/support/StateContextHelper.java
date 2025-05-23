package io.springsecurity.springsecurity6x.security.statemachine.support;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * State Machine과 FactorContext 간의 변환을 돕는 헬퍼 클래스
 */
@Slf4j
@Component
public class StateContextHelper {

    // State Machine 변수 키 상수 (FactorContextStateAdapterImpl과 동일)
    private static final String VAR_USERNAME = "username";
    private static final String VAR_SESSION_ID = "mfaSessionId";
    private static final String VAR_FLOW_TYPE = "flowTypeName";
    private static final String VAR_CURRENT_FACTOR = "currentProcessingFactor";
    private static final String VAR_CURRENT_STEP_ID = "currentStepId";
    private static final String VAR_RETRY_COUNT = "retryCount";
    private static final String VAR_MFA_REQUIRED = "mfaRequiredAsPerPolicy";
    private static final String VAR_COMPLETED_FACTORS = "completedFactors";
    private static final String VAR_AVAILABLE_FACTORS = "availableFactors";
    private static final String VAR_LAST_ERROR = "lastError";

    /**
     * StateContext에서 FactorContext 추출/재구성
     */
    public FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> stateContext) {
        try {
            ExtendedState extendedState = stateContext.getExtendedState();
            Map<Object, Object> variables = extendedState.getVariables();

            // 기본 정보 추출
            String username = (String) variables.get(VAR_USERNAME);
            String sessionId = (String) variables.get(VAR_SESSION_ID);
            String flowTypeName = (String) variables.get(VAR_FLOW_TYPE);

            if (username == null || sessionId == null) {
                log.warn("Essential information missing from StateContext");
                return null;
            }

            // FactorContext 생성 - 실제 생성자 시그니처에 맞게
            // FactorContext(String mfaSessionId, Authentication primaryAuthentication, MfaState initialState, String flowTypeName)

            // Authentication 객체가 필요하므로 StateContext에서 가져오거나 생성해야 함
            // 여기서는 간단히 null로 처리하고 실제 구현 시 수정 필요
            log.warn("Creating FactorContext without proper Authentication object - this needs to be fixed in production");

            // 임시로 Mock Authentication 생성 (실제로는 StateContext에서 가져와야 함)
            org.springframework.security.core.Authentication mockAuth =
                    new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                            username, null, Collections.emptyList()
                    );

            // 현재 상태 가져오기
            MfaState currentState = stateContext.getStateMachine().getState().getId();

            FactorContext context = new FactorContext(
                    sessionId,
                    mockAuth,
                    currentState,
                    flowTypeName
            );

            // 현재 처리 중인 팩터
            String currentFactorStr = (String) variables.get(VAR_CURRENT_FACTOR);
            if (currentFactorStr != null) {
                context.setCurrentProcessingFactor(AuthType.valueOf(currentFactorStr));
            }

            // 기타 필드 설정
            context.setCurrentStepId((String) variables.get(VAR_CURRENT_STEP_ID));

            Integer retryCount = (Integer) variables.get(VAR_RETRY_COUNT);
            context.setRetryCount(retryCount != null ? retryCount : 0);

            Boolean mfaRequired = (Boolean) variables.get(VAR_MFA_REQUIRED);
            context.setMfaRequiredAsPerPolicy(mfaRequired != null ? mfaRequired : false);

            context.setLastError((String) variables.get(VAR_LAST_ERROR));

            // 완료된 팩터들 복원 (AuthenticationStepConfig 리스트)
            String completedFactorsStr = (String) variables.get(VAR_COMPLETED_FACTORS);
            if (completedFactorsStr != null && !completedFactorsStr.isEmpty()) {
                String[] factorEntries = completedFactorsStr.split(",");
                for (String entry : factorEntries) {
                    String[] parts = entry.trim().split(":");
                    if (parts.length >= 3) {
                        String stepId = parts[0];
                        String type = parts[1];
                        int order = Integer.parseInt(parts[2]);

                        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig(
                                flowTypeName != null ? flowTypeName : "mfa",
                                type,
                                order
                        );
                        stepConfig.setStepId(stepId);
                        context.addCompletedFactor(stepConfig);
                    }
                }
            }

            // 사용 가능한 팩터들은 별도 설정이 필요할 수 있음
            // FactorContext의 실제 구조에 따라 수정 필요

            return context;

        } catch (Exception e) {
            log.error("Error extracting FactorContext from StateContext: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * FactorContext 변경사항을 StateContext에 반영
     */
    public void updateStateContext(StateContext<MfaState, MfaEvent> stateContext, FactorContext factorContext) {
        try {
            Map<Object, Object> variables = stateContext.getExtendedState().getVariables();

            // 기본 정보는 변경하지 않음 (username, sessionId, flowTypeName)

            // 변경 가능한 정보들 업데이트
            if (factorContext.getCurrentProcessingFactor() != null) {
                variables.put(VAR_CURRENT_FACTOR, factorContext.getCurrentProcessingFactor().name());
            }

            variables.put(VAR_CURRENT_STEP_ID, factorContext.getCurrentStepId());
            variables.put(VAR_RETRY_COUNT, factorContext.getRetryCount());
            variables.put(VAR_LAST_ERROR, factorContext.getLastError());

            // 완료된 팩터들 (문자열로 저장, stepId:type:order 형식)
            if (factorContext.getCompletedFactors() != null && !factorContext.getCompletedFactors().isEmpty()) {
                String completedFactorsStr = factorContext.getCompletedFactors().stream()
                        .map(step -> step.getStepId() + ":" + step.getType() + ":" + step.getOrder())
                        .collect(Collectors.joining(","));
                variables.put(VAR_COMPLETED_FACTORS, completedFactorsStr);
            }

        } catch (Exception e) {
            log.error("Error updating StateContext from FactorContext: {}", e.getMessage(), e);
        }
    }
}