package io.springsecurity.springsecurity6x.security.mfa.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import jakarta.servlet.ServletException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component // 빈 이름은 클래스 이름의 첫 글자를 소문자로 한 것 (initializeMfaSessionAction)
@RequiredArgsConstructor
public class InitializeMfaSessionAction implements MfaAction {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;

    @Override
    public void execute(MfaProcessingContext context) throws IOException, ServletException {
        FactorContext factorContext = context.getFactorContext();
        Authentication primaryAuth = context.getCurrentAuthentication(); // 1차 인증 성공 후의 Authentication
        AuthenticationFlowConfig flowConfig = context.getFlowConfig();

        Assert.notNull(factorContext, "FactorContext cannot be null in InitializeMfaSessionAction");
        Assert.notNull(primaryAuth, "PrimaryAuthentication (currentAuthentication) cannot be null");
        Assert.notNull(flowConfig, "AuthenticationFlowConfig cannot be null");

        log.info("InitializeMfaSessionAction: Initializing MFA session for user '{}', flow '{}'. Current state in context: {}",
                primaryAuth.getName(), flowConfig.getTypeName(), factorContext.getCurrentState());

        // 1. 사용자가 등록한 MFA 요소 목록을 FactorContext에 설정 (MfaPolicyProvider 사용)
        // 이 정보는 다음 단계(팩터 선택 또는 자동 팩터 시작) 결정에 사용됨.
        List<io.springsecurity.springsecurity6x.security.enums.AuthType> registeredFactors =
                mfaPolicyProvider.getRegisteredMfaFactorsForUser(
                        primaryAuth.getName()
                        // , flowConfig // MfaPolicyProvider의 메소드 시그니처에 따라 flowConfig 전달 여부 결정
                );
        factorContext.setRegisteredMfaFactors(registeredFactors); // FactorContext에 이 메소드가 있다고 가정

        // 2. 1차 인증 자체를 "완료된 단계"로 FactorContext에 기록 (매우 중요!)
        // AuthenticationFlowConfig 에서 1차 인증에 해당하는 AuthenticationStepConfig를 찾아야 함.
        PrimaryAuthenticationOptions primaryOptions = flowConfig.getPrimaryAuthenticationOptions();
        /*if (primaryOptions != null && primaryOptions.getPrimaryAuthStepConfig() != null) {
            AuthenticationStepConfig primaryAuthStepConfig = primaryOptions.getPrimaryAuthStepConfig();
            if (!factorContext.isFactorCompleted(primaryAuthStepConfig.getStepId())) {
                log.info("Recording primary authentication (StepId: '{}', AuthType: '{}') as a completed factor for user '{}'.",
                        primaryAuthStepConfig.getStepId(), primaryAuthStepConfig.getAuthType(), factorContext.getUsername());
                factorContext.addCompletedFactor(primaryAuthStepConfig); // FactorContext가 AuthenticationStepConfig를 받는다고 가정
            }
        } else {
            log.warn("Primary authentication step configuration not found in AuthenticationFlowConfig for flow '{}'. " +
                    "Cannot mark primary authentication as completed in FactorContext.", flowConfig.getTypeName());
        }*/

        // 3. FactorContext의 다른 초기 상태 설정 (예: 재시도 횟수 맵 초기화 등)
        // factorContext.clearCurrentFactorProcessingState(); // 이미 선택된 팩터 정보가 있다면 초기화

        // 4. 변경된 FactorContext 저장
        // HttpServletRequest는 MfaProcessingContext를 통해 접근 가능해야 함
        if (context.getRequest() != null) {
            contextPersistence.saveContext(factorContext, context.getRequest());
            log.debug("InitializeMfaSessionAction: FactorContext initialized/updated and saved for user '{}'.", primaryAuth.getName());
        } else {
            log.warn("InitializeMfaSessionAction: HttpServletRequest is null in MfaProcessingContext. FactorContext changes might not be persisted to session.");
        }
    }
}