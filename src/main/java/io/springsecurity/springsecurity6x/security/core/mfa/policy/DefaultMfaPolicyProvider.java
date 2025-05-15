package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    // 실제 운영 환경에서는 사용자별 MFA 설정을 DB 등에서 조회하는 서비스 필요
    // private final UserMfaSettingsService userMfaSettingsService;
    private final MfaWorkflowService mfaWorkflowService; // 사용자별 등록 Factor 조회 등을 위해 (가상)

    @Override
    public void evaluateMfaPolicy(FactorContext ctx) {
        if (ctx == null || ctx.getUsername() == null) {
            log.warn("Cannot evaluate MFA policy without a valid FactorContext or username.");
            ctx.setMfaRequired(false); // 안전한 기본값
            return;
        }
        String username = ctx.getUsername();

        // 1. 이 사용자가 MFA를 사용해야 하는가? (예: 사용자 속성, 그룹 정책, Risk 등 기반)
        //    여기서는 특정 사용자만 MFA를 사용한다고 가정
        boolean mfaActuallyRequired = determineIfMfaIsActuallyRequiredForUser(username);
        ctx.setMfaRequired(mfaActuallyRequired);

        if (mfaActuallyRequired) {
            // 2. 사용자가 등록한 MFA 수단 조회
            Set<AuthType> registeredFactors = mfaWorkflowService.getRegisteredMfaFactorsForUser(username);
            ctx.setRegisteredMfaFactors(registeredFactors != null ? EnumSet.copyOf(registeredFactors) : EnumSet.noneOf(AuthType.class));

            if (CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
                log.warn("MFA is required for user '{}', but no MFA factors are registered. MFA cannot proceed.", username);
                // 이 경우, 관리자에게 알리거나 사용자에게 Factor 등록을 유도하는 흐름으로 보내야 함.
                // 여기서는 MFA 진행 불가로 처리.
                ctx.setMfaRequired(false); // MFA 진행 불가
            } else {
                // 3. (선택적) 자동 시도할 우선 Factor 결정 (예: Passkey Conditional UI)
                // ctx.setPreferredAutoAttemptFactor(determinePreferredAutoAttemptFactor(username, registeredFactors));
                log.info("MFA policy evaluated for user {}: MFA Required={}, Registered Factors={}",
                        username, ctx.isMfaRequired(), ctx.getRegisteredMfaFactors());
            }
        } else {
            log.info("MFA policy evaluated for user {}: MFA Not Required.", username);
            ctx.setRegisteredMfaFactors(EnumSet.noneOf(AuthType.class));
        }
    }

    private boolean determineIfMfaIsActuallyRequiredForUser(String username) {
        // TODO: 실제 사용자별 MFA 강제 여부 로직 구현 (DB 조회, 사용자 설정, 그룹 정책 등)
        // 예시: 'mfa_user'만 MFA를 사용한다고 가정
        return "mfa_user".equals(username) || "user_mfa@example.com".equals(username);
    }

    private AuthType determinePreferredAutoAttemptFactor(String username, Set<AuthType> registeredFactors) {
        // TODO: 사용자의 우선 설정이나 정책에 따라 자동 시도 Factor 결정
        if (registeredFactors.contains(AuthType.PASSKEY)) {
            return AuthType.PASSKEY; // Passkey가 등록되어 있으면 우선 시도
        }
        return null;
    }

    @Override
    public AuthType determineNextFactor(FactorContext ctx) {
        if (!ctx.isMfaRequired() || CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return null; // MFA 불필요 또는 등록된 Factor 없음
        }

        // 이미 완료된 Factor 들을 제외하고, 남은 Factor 중 정책에 따라 다음 Factor 결정
        // 이 예제에서는 간단히 등록된 Factor 중 첫 번째 미완료 Factor를 선택 (순서 중요)
        // 실제로는 FactorContext에 완료된 Factor 목록을 기록하고,
        // 사용자의 선호도나 보안 정책에 따라 다음 Factor를 동적으로 결정해야 함.

        List<AuthType> processingOrder = List.of(AuthType.OTT, AuthType.PASSKEY); // 예시 처리 순서

        for (AuthType factorInOrder : processingOrder) {
            if (ctx.getRegisteredMfaFactors().contains(factorInOrder) &&
                    !isFactorCompleted(ctx, factorInOrder)) {
                log.debug("Next MFA factor determined for user {}: {}", ctx.getUsername(), factorInOrder);
                return factorInOrder;
            }
        }
        log.debug("No more MFA factors to process for user {}. All registered factors seem completed.", ctx.getUsername());
        return null; // 모든 등록된 (그리고 처리 순서에 있는) Factor 완료
    }

    private boolean isFactorCompleted(FactorContext ctx, AuthType factorType) {
        // FactorContext의 mfaAttemptHistory 등을 참조하여 해당 factor가 성공적으로 완료되었는지 확인
        // 이 예시에서는 단순화를 위해, 한 번 성공하면 완료된 것으로 간주
        return ctx.getMfaAttemptHistory().stream()
                .anyMatch(attempt -> attempt.getFactorType() == factorType && attempt.isSuccess());
    }


    @Override
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        // TODO: Factor 타입별 또는 사용자별 재시도 정책 반환
        // 예시: 기본 3회 시도
        return new RetryPolicy(3);
    }

    @Override
    public boolean isMfaRequired(FactorContext ctx) {
        // evaluateMfaPolicy 에서 이미 ctx.isMfaRequired()가 설정됨
        return ctx.isMfaRequired();
    }

    @Override
    public Set<AuthType> getRegisteredMfaFactors(FactorContext ctx) {
        // evaluateMfaPolicy 에서 이미 ctx.getRegisteredMfaFactors()가 설정됨
        return Collections.unmodifiableSet(ctx.getRegisteredMfaFactors());
    }

    @Override
    public AuthType getPreferredAutoAttemptFactor(FactorContext ctx) {
        // evaluateMfaPolic y에서 이미 ctx.getPreferredAutoAttemptFactor()가 설정됨
        return ctx.getPreferredAutoAttemptFactor();
    }
}
