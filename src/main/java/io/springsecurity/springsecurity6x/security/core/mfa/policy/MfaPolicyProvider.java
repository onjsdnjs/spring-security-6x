package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

public interface MfaPolicyProvider {

    /**
     * 1차 인증 성공 후, 사용자의 MFA 요구사항을 평가하고 초기 FactorContext를 설정합니다.
     * 이 메서드는 FactorContext의 mfaRequiredAsPerPolicy, registeredMfaFactors,
     * currentProcessingFactor (만약 첫 번째 Factor가 정책에 의해 결정될 수 있다면),
     * 그리고 초기 currentMfaState 등을 설정해야 합니다.
     *
     * @param primaryAuthentication 1차 인증 성공 객체
     * @param ctx                   새로 생성된 FactorContext (이 메서드 내에서 필드들이 채워짐)
     */
    void evaluateMfaRequirementAndDetermineInitialStep(Authentication primaryAuthentication, FactorContext ctx);

    /**
     * 현재 FactorContext (완료된 Factor 목록 포함)를 기반으로 다음에 처리해야 할 MFA Factor 타입을 결정합니다.
     * 더 이상 진행할 Factor가 없으면 null을 반환하여 모든 MFA 단계가 완료되었음을 나타냅니다.
     *
     * @param ctx 현재 FactorContext
     * @return 다음으로 진행할 AuthType 또는 모든 Factor 완료 시 null
     */
    @Nullable
    AuthType determineNextFactorToProcess(FactorContext ctx);

    @Nullable
    RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx);

}
