package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication; // 추가
import org.springframework.stereotype.Component; // @Component 추가
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component // 빈으로 등록
@RequiredArgsConstructor
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    private final UserRepository userRepository;

    @Override
    public void evaluateMfaRequirementAndDetermineInitialStep(Authentication primaryAuthentication, FactorContext ctx) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        Assert.isTrue(Objects.equals(primaryAuthentication.getName(), ctx.getUsername()),
                "Username in FactorContext must match primaryAuthentication's name.");

        String username = ctx.getUsername();
        Optional<Users> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            log.warn("User {} not found. MFA cannot be evaluated.", username);
            ctx.setMfaRequiredAsPerPolicy(false);
            ctx.setCurrentMfaState(MfaState.NONE); // 또는 적절한 실패 상태
            return;
        }

        Users user = userOptional.get();
        boolean mfaEnabledForUser = user.isMfaEnabled();
        ctx.setMfaRequiredAsPerPolicy(mfaEnabledForUser);

        if (mfaEnabledForUser) {
            Set<AuthType> registeredFactors = parseRegisteredMfaFactors(user.getMfaFactors());
            ctx.setRegisteredMfaFactors(registeredFactors.isEmpty() ? EnumSet.noneOf(AuthType.class) : EnumSet.copyOf(registeredFactors));

            if (CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
                log.warn("MFA is enabled for user '{}', but no MFA factors are registered. MFA cannot proceed.", username);
                ctx.setMfaRequiredAsPerPolicy(false); // 실제 진행 불가하므로 MFA 요구 안 함으로 변경
                ctx.setCurrentMfaState(MfaState.NONE); // 또는 MFA_FAILED_TERMINAL (설정 오류)
            } else {
                // 첫 번째 처리할 Factor 결정 (예: 정책에 따라 또는 등록된 첫 번째 Factor)
                AuthType initialFactor = determineNextFactorToProcessInternal(ctx.getRegisteredMfaFactors(), ctx.getCompletedMfaFactors());
                if (initialFactor != null) {
                    ctx.setCurrentProcessingFactor(initialFactor);
                    ctx.setCurrentMfaState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
                    log.info("MFA required for user {}. Initial factor: {}, Initial state: {}. Session: {}",
                            username, initialFactor, ctx.getCurrentMfaState(), ctx.getMfaSessionId());
                } else {
                    // 등록된 Factor는 있지만, 정책상 진행할 첫 Factor가 없는 이상한 경우 (또는 모두 이미 완료된 것처럼?)
                    // 이 경우는 거의 발생하지 않아야 함. 등록된 Factor가 있다면 하나는 진행 가능해야 함.
                    log.warn("MFA required for user '{}', registered factors exist, but no initial factor determined. Defaulting to AWAITING_FACTOR_SELECTION. Session: {}",
                            username, ctx.getMfaSessionId());
                    ctx.setCurrentMfaState(MfaState.AWAITING_FACTOR_SELECTION);
                }
            }
        } else {
            log.info("MFA not enabled for user {}. Session: {}", username, ctx.getMfaSessionId());
            ctx.setCurrentMfaState(MfaState.NONE); // MFA 불필요
        }
    }

    private Set<AuthType> parseRegisteredMfaFactors(String mfaFactorsString) {
        if (StringUtils.hasText(mfaFactorsString)) {
            try {
                return Arrays.stream(mfaFactorsString.split(","))
                        .map(String::trim)
                        .map(String::toUpperCase)
                        .map(AuthType::valueOf)
                        .collect(Collectors.toCollection(() -> EnumSet.noneOf(AuthType.class)));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid AuthType string found in mfaFactors: '{}'", mfaFactorsString, e);
                return EnumSet.noneOf(AuthType.class);
            }
        }
        return EnumSet.noneOf(AuthType.class);
    }

    @Override
    @Nullable
    public AuthType determineNextFactorToProcess(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");
        if (!ctx.isMfaRequiredAsPerPolicy() || CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return null; // MFA가 필요 없거나 등록된 Factor가 없으면 다음 Factor 없음
        }
        return determineNextFactorToProcessInternal(ctx.getRegisteredMfaFactors(), ctx.getCompletedMfaFactors());
    }

    /**
     * 실제 다음 Factor를 결정하는 내부 로직.
     * 등록된 Factor 중 아직 완료되지 않은 것을 우선순위에 따라 반환.
     */
    @Nullable
    private AuthType determineNextFactorToProcessInternal(Set<AuthType> registeredFactors, Set<AuthType> completedFactors) {
        // 예시: 우선순위 (Passkey > OTT > RecoveryCode)
        // 실제 우선순위는 플랫폼 정책에 따라 설정 가능
        List<AuthType> processingOrder = List.of(AuthType.PASSKEY, AuthType.OTT, AuthType.RECOVERY_CODE);

        for (AuthType factorInOrder : processingOrder) {
            if (registeredFactors.contains(factorInOrder) && !completedFactors.contains(factorInOrder)) {
                log.debug("Next MFA factor determined: {}", factorInOrder);
                return factorInOrder;
            }
        }
        log.debug("No more MFA factors to process. All registered and required factors seem completed.");
        return null; // 모든 등록된 Factor가 완료되었거나, 진행할 Factor가 없음
    }

    @Override
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        Assert.notNull(factorType, "FactorType cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        // 실제로는 factorType 또는 사용자 등급별로 다른 재시도 정책 반환 가능
        log.debug("Providing default retry policy (3 attempts) for factor {} (user {}, session {})",
                factorType, ctx.getUsername(), ctx.getMfaSessionId());
        return new RetryPolicy(3); // 기본 3회
    }
}