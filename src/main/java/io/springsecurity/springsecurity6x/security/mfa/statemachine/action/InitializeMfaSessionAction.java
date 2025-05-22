package io.springsecurity.springsecurity6x.security.mfa.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType; // AuthType 사용을 위해 import
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest; // 추가
import jakarta.servlet.http.HttpServletResponse; // 추가
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils; // 추가
import org.springframework.util.StringUtils; // 추가

import java.io.IOException;
import java.util.List;
import java.util.Optional; // 추가

@Slf4j
@Component("initializeMfaSessionAction")
@RequiredArgsConstructor
public class InitializeMfaSessionAction implements MfaAction {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;

    @Override
    public void execute(MfaProcessingContext context) throws IOException, ServletException {
        FactorContext factorContext = context.getFactorContext(); // MfaProcessingContext에 getFactorContext()가 있다고 가정
        Authentication primaryAuth = context.getCurrentAuthentication();
        AuthenticationFlowConfig flowConfig = context.getFlowConfig(); // MfaProcessingContext에 getFlowConfig()가 있다고 가정
        HttpServletRequest request = context.getRequest(); // MfaProcessingContext에 getRequest()가 있다고 가정

        Assert.notNull(factorContext, "FactorContext cannot be null in InitializeMfaSessionAction");
        Assert.notNull(primaryAuth, "PrimaryAuthentication (currentAuthentication) cannot be null");
        Assert.notNull(flowConfig, "AuthenticationFlowConfig cannot be null");
        Assert.notNull(request, "HttpServletRequest cannot be null for saving context");

        log.info("InitializeMfaSessionAction: Initializing MFA session for user '{}', flow '{}'. Current state in context: {}",
                primaryAuth.getName(), flowConfig.getTypeName(), factorContext.getCurrentState());

        // 1. 사용자가 등록한 MFA 요소 목록을 FactorContext에 설정
        List<AuthType> registeredFactors = mfaPolicyProvider.getRegisteredMfaFactorsForUser(
                primaryAuth.getName()
                // , flowConfig // MfaPolicyProvider.getRegisteredMfaFactorsForUser 시그니처에 따라 flowConfig 전달
        );
        // FactorContext에 setRegisteredMfaFactors(List<AuthType>) 메소드가 있다고 가정
        factorContext.setRegisteredMfaFactors(registeredFactors);
        log.debug("Set registered factors for user {}: {}", primaryAuth.getName(), registeredFactors);

        // 2. 1차 인증 자체를 "완료된 단계"로 FactorContext에 기록 (기존 설계 최대한 활용)
        PrimaryAuthenticationOptions primaryOptions = flowConfig.getPrimaryAuthenticationOptions(); // AuthenticationFlowConfig에 이 getter가 있다고 가정

        if (primaryOptions != null) {
            AuthType primaryAuthType = primaryOptions.getPrimaryAuthType(); // PrimaryAuthenticationOptions에 이 getter가 있다고 가정
            if (primaryAuthType != null && !CollectionUtils.isEmpty(flowConfig.getStepConfigs())) { // AuthenticationFlowConfig에 getSteps()가 있다고 가정
                // 1차 인증으로 사용된 AuthType과 일치하는 첫 번째 AuthenticationStepConfig를 찾음
                // (이것이 1차 인증 스텝이라는 강력한 가정이 필요함. DSL 설정 시 1차 인증 스텝이 명확히 steps에 추가되어야 함)
                Optional<AuthenticationStepConfig> primaryAuthStepConfigOpt = flowConfig.getStepConfigs().stream()
                        .filter(step -> step != null && primaryAuthType.equals(step.getAuthType())) // AuthenticationStepConfig에 getAuthType() 가정
                        .findFirst();

                if (primaryAuthStepConfigOpt.isPresent()) {
                    AuthenticationStepConfig primaryAuthStepConfig = primaryAuthStepConfigOpt.get();
                    if (StringUtils.hasText(primaryAuthStepConfig.getStepId()) && // stepId가 있는지 확인
                            !factorContext.isFactorCompleted(primaryAuthStepConfig.getStepId())) { // FactorContext에 isFactorCompleted(String) 가정
                        log.info("Recording primary authentication (StepId: '{}', AuthType: '{}') as a completed factor for user '{}'.",
                                primaryAuthStepConfig.getStepId(), primaryAuthStepConfig.getAuthType(), factorContext.getUsername());
                        // FactorContext.addCompletedFactor는 AuthenticationStepConfig를 받는다고 가정 (사용자 이전 지적 반영)
                        factorContext.addCompletedFactor(primaryAuthStepConfig);
                    } else if (!StringUtils.hasText(primaryAuthStepConfig.getStepId())) {
                        log.error("Primary authentication step (AuthType: {}) for flow '{}' is missing a stepId. Cannot mark as completed.",
                                primaryAuthType, flowConfig.getTypeName());
                    }
                } else {
                    log.warn("No AuthenticationStepConfig found for primary authentication type {} in flow '{}'. " +
                                    "Cannot mark primary authentication as completed in FactorContext.",
                            primaryAuthType, flowConfig.getTypeName());
                }
            } else {
                log.warn("Primary authentication type is not defined or no steps in flow '{}'. " +
                        "Cannot determine primary authentication step to mark as completed.", flowConfig.getTypeName());
            }
        } else {
            log.warn("PrimaryAuthenticationOptions not found in AuthenticationFlowConfig for flow '{}'. " +
                    "Cannot mark primary authentication as completed in FactorContext.", flowConfig.getTypeName());
        }

        // 3. FactorContext의 다른 초기 상태 설정 (예: 재시도 횟수 맵 초기화)
        if (factorContext.getCurrentFactorOptions() != null || factorContext.getCurrentProcessingFactor() != null || factorContext.getCurrentStepId() != null) {
            // FactorContext에 clearCurrentFactorProcessingState() 메소드가 있다고 가정
            factorContext.clearCurrentFactorProcessingState();
            log.debug("Cleared current factor processing state for user '{}'.", primaryAuth.getName());
        }


        // 4. 변경된 FactorContext 저장
        // contextPersistence.saveContext는 첫 번째 인자로 FactorContext, 두 번째 인자로 HttpServletRequest를 받는다고 가정
        contextPersistence.saveContext(factorContext, request);
        log.debug("InitializeMfaSessionAction: FactorContext initialized/updated and saved for user '{}'.", primaryAuth.getName());
    }
}