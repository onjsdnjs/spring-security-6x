package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    private final UserRepository userRepository;

    @Override
    public void evaluateMfaPolicy(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null for MFA policy evaluation.");
        if (ctx.getUsername() == null) {
            log.warn("Cannot evaluate MFA policy: username is null in FactorContext. Session: {}", ctx.getMfaSessionId());
            ctx.setMfaRequired(false);
            return;
        }
        String username = ctx.getUsername();

        boolean mfaActuallyRequired = determineIfMfaIsActuallyRequiredForUser(username, ctx);
        ctx.setMfaRequired(mfaActuallyRequired);

        if (mfaActuallyRequired) {
            Set<AuthType> registeredFactors = getRegisteredMfaFactorsForUser(username);
            // FactorContext에 사용자의 등록된 MFA 요소 설정
            ctx.setRegisteredMfaFactors(registeredFactors != null ? EnumSet.copyOf(registeredFactors) : EnumSet.noneOf(AuthType.class));

            if (CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
                log.warn("MFA is required for user '{}' (session {}), but no MFA factors are registered. MFA cannot proceed.", username, ctx.getMfaSessionId());
                ctx.setMfaRequired(false); // 등록된 요소가 없으면 MFA를 요구할 수 없음
            } else {
                // getPreferredAutoAttemptFactor(FactorContext ctx) 호출로 변경
                ctx.setPreferredAutoAttemptFactor(getPreferredAutoAttemptFactor(ctx));
                log.info("MFA policy evaluated for user {}: MFA Required={}, Registered Factors={}, PreferredAutoAttempt={}. Session: {}",
                        username, ctx.isMfaRequired(), ctx.getRegisteredMfaFactors(), ctx.getPreferredAutoAttemptFactor(), ctx.getMfaSessionId());
            }
        } else {
            log.info("MFA policy evaluated for user {}: MFA Not Required. Session: {}", username, ctx.getMfaSessionId());
            ctx.setRegisteredMfaFactors(EnumSet.noneOf(AuthType.class)); // MFA가 필요 없으면 등록된 요소도 없음으로 처리
            ctx.setPreferredAutoAttemptFactor(null); // 선호 자동 시도 요소도 없음으로 처리
        }
    }

    private boolean determineIfMfaIsActuallyRequiredForUser(String username, FactorContext ctx) {
        return userRepository.findByUsername(username)
                .map(Users::isMfaEnabled)
                .orElse(false);
    }

    @Override
    public Set<AuthType> getRegisteredMfaFactors(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null for getting registered MFA factors.");
        Assert.hasText(ctx.getUsername(), "Username in FactorContext cannot be empty.");
        return getRegisteredMfaFactorsForUser(ctx.getUsername());
    }

    private Set<AuthType> getRegisteredMfaFactorsForUser(String username) {
        Assert.hasText(username, "Username cannot be empty for fetching registered MFA factors");
        log.debug("DefaultMfaPolicyProvider: Fetching registered MFA factors for user {}", username);

        return userRepository.findByUsername(username)
                .map(user -> {
                    String mfaFactorsString = user.getMfaFactors();
                    if (StringUtils.hasText(mfaFactorsString)) {
                        try {
                            return Arrays.stream(mfaFactorsString.split(","))
                                    .map(String::trim)
                                    .map(String::toUpperCase)
                                    .map(AuthType::valueOf)
                                    .collect(Collectors.toCollection(() -> EnumSet.noneOf(AuthType.class)));
                        } catch (IllegalArgumentException e) {
                            log.warn("Invalid AuthType string found in mfaFactors for user {}: '{}'", username, mfaFactorsString, e);
                            return EnumSet.noneOf(AuthType.class);
                        }
                    }
                    return EnumSet.noneOf(AuthType.class);
                })
                .orElseGet(() -> {
                    log.warn("User {} not found for fetching registered MFA factors.", username);
                    return EnumSet.noneOf(AuthType.class);
                });
    }


    @Override
    public AuthType determineNextFactor(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null for determining next factor.");
        if (!ctx.isMfaRequired() || CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return null;
        }
        List<AuthType> processingOrder = List.of(AuthType.PASSKEY, AuthType.OTT); // 예시 순서

        for (AuthType factorInOrder : processingOrder) {
            if (ctx.getRegisteredMfaFactors().contains(factorInOrder) && !isFactorCompleted(ctx, factorInOrder)) {
                log.debug("Next MFA factor determined for user {}: {}. Session: {}", ctx.getUsername(), factorInOrder, ctx.getMfaSessionId());
                return factorInOrder;
            }
        }
        log.debug("No more MFA factors to process for user {}. All registered factors seem completed. Session: {}", ctx.getUsername(), ctx.getMfaSessionId());
        return null;
    }

    private boolean isFactorCompleted(FactorContext ctx, AuthType factorType) {
        Assert.notNull(ctx, "FactorContext cannot be null for checking if factor is completed.");
        return ctx.getMfaAttemptHistory().stream()
                .anyMatch(attempt -> Objects.equals(attempt.getFactorType(), factorType) && attempt.isSuccess());
    }

    @Override
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        Assert.notNull(factorType, "FactorType cannot be null for getting retry policy.");
        Assert.notNull(ctx, "FactorContext cannot be null for getting retry policy.");
        log.debug("Providing default retry policy for factor {} (user {}, session {})", factorType, ctx.getUsername(), ctx.getMfaSessionId());
        return new RetryPolicy(3);
    }

    @Override
    public boolean isMfaRequired(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null for checking if MFA is required.");
        return ctx.isMfaRequired();
    }

    @Override
    public AuthType getPreferredAutoAttemptFactor(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null for getting preferred auto-attempt factor.");
        if (ctx.getRegisteredMfaFactors().contains(AuthType.PASSKEY)) {
            return AuthType.PASSKEY;
        }
        return null;
    }
}