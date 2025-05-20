package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig; // 추가
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig; // 추가
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions; // 추가
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext; // 추가
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
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
    private final ApplicationContext applicationContext; // AuthenticationFlowConfig 접근용

    @Override
    public void evaluateMfaRequirementAndDetermineInitialStep(Authentication primaryAuthentication, FactorContext ctx) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        Assert.isTrue(Objects.equals(primaryAuthentication.getName(), ctx.getUsername()),
                "Username in FactorContext must match primaryAuthentication's name.");
        // 초기 상태는 PRIMARY_AUTHENTICATION_COMPLETED 여야 함.
        Assert.isTrue(ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED,
                "evaluateMfaRequirementAndDetermineInitialStep should be called when FactorContext state is PRIMARY_AUTHENTICATION_COMPLETED.");

        String username = ctx.getUsername();
        Optional<Users> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            log.warn("User {} not found. MFA policy evaluation cannot proceed.", username);
            ctx.setMfaRequiredAsPerPolicy(false);
            ctx.changeState(MfaState.ALL_FACTORS_COMPLETED); // MFA 불필요
            return;
        }

        Users user = userOptional.get();
        boolean mfaEnabledForUser = user.isMfaEnabled();
        ctx.setMfaRequiredAsPerPolicy(mfaEnabledForUser);

        if (mfaEnabledForUser) {
            Set<AuthType> registeredFactors = parseRegisteredMfaFactorsFromUser(user);
            ctx.setRegisteredMfaFactors(registeredFactors.isEmpty() ? EnumSet.noneOf(AuthType.class) : EnumSet.copyOf(registeredFactors));

            if (CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
                log.warn("MFA is enabled for user '{}', but no MFA factors are registered in DB. MFA cannot proceed.", username);
                ctx.setMfaRequiredAsPerPolicy(false);
                ctx.changeState(MfaState.ALL_FACTORS_COMPLETED);
            } else {
                AuthType initialFactor = determineNextFactorInternal(ctx.getRegisteredMfaFactors(), ctx.getCompletedMfaFactors());
                if (initialFactor != null) {
                    ctx.setCurrentProcessingFactor(initialFactor);
                    // 현재 MFA Flow의 AuthenticationFlowConfig를 찾아 해당 Factor의 Options 설정
                    AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
                    if (mfaFlowConfig != null && mfaFlowConfig.getRegisteredFactorOptions() != null) {
                        AuthenticationProcessingOptions factorOptions = mfaFlowConfig.getRegisteredFactorOptions().get(initialFactor);
                        ctx.setCurrentFactorOptions(factorOptions);
                        if (factorOptions == null) {
                            log.warn("No AuthenticationProcessingOptions found for initial factor {} in MFA flow config for user {}.", initialFactor, username);
                        }
                    } else {
                        log.warn("MFA FlowConfig or registeredFactorOptions not found. Cannot set currentFactorOptions for user {}.", username);
                    }
                    ctx.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
                    log.info("MFA required for user {}. Initial factor set to: {}. New state: {}. Session: {}",
                            username, initialFactor, ctx.getCurrentState(), ctx.getMfaSessionId());
                } else {
                    log.warn("MFA required for user '{}', registered factors exist, but no initial factor determined. Proceeding to factor selection. Session: {}",
                            username, ctx.getMfaSessionId());
                    ctx.setCurrentProcessingFactor(null);
                    ctx.setCurrentFactorOptions(null);
                    ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                }
            }
        } else {
            log.info("MFA not enabled for user {}. No MFA required. Session: {}", username, ctx.getMfaSessionId());
            ctx.changeState(MfaState.ALL_FACTORS_COMPLETED);
        }
    }

    // ... (parseRegisteredMfaFactorsFromUser, determineNextFactorInternal, getRetryPolicyForFactor, isFactorAvailableForUser는 이전과 유사하게 유지) ...
    private Set<AuthType> parseRegisteredMfaFactorsFromUser(Users user) {
        String mfaFactorsString = user.getMfaFactors();
        if (StringUtils.hasText(mfaFactorsString)) {
            try {
                return Arrays.stream(mfaFactorsString.split(","))
                        .map(String::trim)
                        .map(String::toUpperCase)
                        .map(AuthType::valueOf)
                        .collect(Collectors.toCollection(() -> EnumSet.noneOf(AuthType.class)));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid AuthType string found in mfaFactors for user {}: '{}'", user.getUsername(), mfaFactorsString, e);
                return EnumSet.noneOf(AuthType.class);
            }
        }
        return EnumSet.noneOf(AuthType.class);
    }

    @Nullable
    @Override
    public AuthType determineNextFactorToProcess(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");
        if (!ctx.isMfaRequiredAsPerPolicy() || CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return null;
        }
        AuthType nextFactor = determineNextFactorInternal(ctx.getRegisteredMfaFactors(), ctx.getCompletedMfaFactors());
        // 다음 Factor가 결정되면, FactorContext에 currentFactorOptions도 설정해야 함 (호출하는 쪽에서)
        return nextFactor;
    }

    @Nullable
    private AuthType determineNextFactorInternal(Set<AuthType> registered, Set<AuthType> completed) {
        List<AuthType> processingOrder = List.of(AuthType.PASSKEY, AuthType.OTT, AuthType.RECOVERY_CODE);
        for (AuthType factorInOrder : processingOrder) {
            if (registered.contains(factorInOrder) && (completed == null || !completed.contains(factorInOrder))) {
                log.debug("Next MFA factor determined by policy: {}", factorInOrder);
                return factorInOrder;
            }
        }
        log.debug("No more MFA factors to process based on policy. All registered and required factors might be completed.");
        return null;
    }

    @Override
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        Assert.notNull(factorType, "FactorType cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        log.debug("Providing default retry policy (3 attempts) for factor {} (user {}, session {})",
                factorType, ctx.getUsername(), ctx.getMfaSessionId());
        return new RetryPolicy(3);
    }

    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");
        if (ctx != null && !CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return ctx.getRegisteredMfaFactors().contains(factorType);
        }
        return userRepository.findByUsername(username)
                .map(user -> parseRegisteredMfaFactorsFromUser(user).contains(factorType))
                .orElse(false);
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig() {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            return platformConfig.getFlows().stream()
                    .filter(flow -> "mfa".equalsIgnoreCase(flow.getTypeName()))
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            log.error("Could not retrieve PlatformConfig or MFA flow configuration for setting factor options.", e);
            return null;
        }
    }
}