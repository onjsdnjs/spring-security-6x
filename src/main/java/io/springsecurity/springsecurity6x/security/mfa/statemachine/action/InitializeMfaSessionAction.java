package io.springsecurity.springsecurity6x.security.mfa.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;

@Slf4j
@Component("initializeMfaSessionAction") // 빈 이름 명시
@RequiredArgsConstructor
public class InitializeMfaSessionAction implements MfaAction {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider; // 초기 팩터 목록 설정 등에 사용

    @Override
    public void execute(MfaProcessingContext context) throws IOException {
        Authentication primaryAuth = context.getCurrentAuthentication();
        AuthenticationFlowConfig flowConfig = context.getFlowConfig();
        FactorContext factorContext = context.getFactorContext(); // startOrContinueFlow에서 이미 생성/로드되어 전달됨

        Assert.notNull(primaryAuth, "PrimaryAuthentication cannot be null for InitializeMfaSessionAction");
        Assert.notNull(flowConfig, "AuthenticationFlowConfig cannot be null");
        Assert.notNull(factorContext, "FactorContext cannot be null");

        log.info("InitializeMfaSessionAction: Initializing MFA session for user '{}', flow '{}'. Current state: {}",
                primaryAuth.getName(), flowConfig.getTypeName(), factorContext.getCurrentState());

        // FactorContext의 registeredMfaFactors 설정 (MfaPolicyProvider를 통해 가져옴)
        // 이 로직은 MfaPolicyProvider.shouldApplyMfa 에서 이미 수행되었을 수 있음. 중복 호출 방지.
        if (factorContext.getRegisteredMfaFactors().isEmpty()) {
            factorContext.setRegisteredMfaFactors(
                    mfaPolicyProvider.getRegisteredMfaFactorsForUser(
                            primaryAuth.getName()
                            // , flowConfig // MfaPolicyProvider 메소드 시그니처에 따라
                    )
            );
        }

        // 1차 인증 자체를 완료된 팩터로 기록해야 하는지 여부는 설계에 따라 다름.
        // 만약 1차 인증도 AuthenticationStepConfig로 정의되고, checkAllFactorsCompleted에서
        // 이를 포함하여 검사한다면, 여기서 1차 인증 스텝을 완료 처리해야 함.
        // 예:
        // AuthenticationStepConfig primaryAuthStep = flowConfig.getPrimaryAuthenticationStep(); // 이 메소드가 있다고 가정
        // if (primaryAuthStep != null) {
        //    factorContext.addCompletedFactor(primaryAuthStep);
        // }


        // 초기 상태 변경 (예: START_MFA -> PRIMARY_AUTHENTICATION_SUCCESSFUL)은
        // 이 액션을 호출한 전이(Transition)에서 이미 발생했을 것임.
        // 여기서는 FactorContext의 내부 상태를 초기화하거나, 필요한 정보를 설정.
        // 예: factorContext.clearCurrentFactorProcessingState(); (이미 선택된 팩터 정보 초기화)

        // 변경된 FactorContext 저장
        contextPersistence.saveContext(context.getRequest(), factorContext);
        log.debug("InitializeMfaSessionAction: FactorContext initialized and saved for user '{}'.", primaryAuth.getName());
    }
}
