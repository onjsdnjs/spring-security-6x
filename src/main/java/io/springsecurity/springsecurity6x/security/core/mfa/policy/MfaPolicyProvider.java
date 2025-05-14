package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.lang.Nullable;

import java.util.Set;

/**
 * MFA 정책을 결정하고 제공하는 인터페이스.
 * 예를 들어, 사용자의 다음 인증 Factor를 결정하거나, Factor별 재시도 정책을 반환합니다.
 */
public interface MfaPolicyProvider {

    /**
     * 현재 FactorContext를 기반으로 다음으로 진행해야 할 MFA Factor 타입을 결정합니다.
     * 더 이상 진행할 Factor가 없으면 null을 반환해야 합니다.
     *
     * @param ctx 현재 FactorContext
     * @return 다음으로 진행할 AuthType 또는 null
     */
    @Nullable
    AuthType determineNextFactor(FactorContext ctx);

    /**
     * 특정 인증 요소(Factor)에 대한 재시도 정책을 반환합니다.
     *
     * @param factorType 재시도 정책을 조회할 AuthType
     * @param ctx 현재 FactorContext (사용자별 또는 상황별 정책 적용 시 필요할 수 있음)
     * @return 해당 Factor에 대한 RetryPolicy 객체. 정책이 없으면 null을 반환할 수 있습니다.
     */
    @Nullable
    RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx);

    /**
     * 특정 사용자에 대해 MFA 인증이 요구되는지 여부를 결정합니다.
     * @param ctx 현재 FactorContext (사용자 정보 포함)
     * @return MFA가 요구되면 true, 그렇지 않으면 false
     */
    boolean isMfaRequired(FactorContext ctx);

    /**
     * 특정 사용자에 대해 등록된/사용 가능한 MFA 요소 목록을 반환합니다.
     * @param ctx 현재 FactorContext
     * @return 사용 가능한 AuthType의 Set
     */
    Set<AuthType> getRegisteredMfaFactors(FactorContext ctx);

    /**
     * 정책에 따라 자동으로 시도할 첫 번째 MFA 요소를 결정합니다.
     * @param ctx 현재 FactorContext
     * @return 자동으로 시도할 AuthType, 없으면 null
     */
    @Nullable
    AuthType getPreferredAutoAttemptFactor(FactorContext ctx);

    // 기타 필요한 정책 관련 메소드 추가 가능
}
