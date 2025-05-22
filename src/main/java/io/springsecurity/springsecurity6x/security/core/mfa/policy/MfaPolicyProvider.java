package io.springsecurity.springsecurity6x.security.core.mfa.policy;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.util.List;

public interface MfaPolicyProvider {

    // 기존 evaluateMfaRequirementAndDetermineInitialStep 유지
    void evaluateMfaRequirementAndDetermineInitialStep(Authentication primaryAuthentication, FactorContext ctx);

    // 기존 determineNextFactorToProcess 유지
    @Nullable
    void determineNextFactorToProcess(FactorContext ctx);

    void checkAllFactorsCompleted(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig);
    // 기존 getRetryPolicyForFactor 유지
    @Nullable
    RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx);

    List<AuthType> getRegisteredMfaFactorsForUser(String username);

    // 추가: 특정 사용자에 대해 특정 Factor가 사용 가능한지 (등록되었고 활성화 상태인지 등) 확인
    boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx);

    RetryPolicy getRetryPolicy(FactorContext factorContext, AuthenticationStepConfig step);
}
