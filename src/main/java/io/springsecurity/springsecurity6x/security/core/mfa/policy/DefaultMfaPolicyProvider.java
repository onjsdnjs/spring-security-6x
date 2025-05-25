package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    private final UserRepository userRepository;
    private final ApplicationContext applicationContext;

    @Override
    public void evaluateMfaRequirementAndDetermineInitialStep(Authentication primaryAuthentication, FactorContext ctx) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        Assert.isTrue(Objects.equals(primaryAuthentication.getName(), ctx.getUsername()),
                "Username mismatch in FactorContext and Authentication");

        String username = primaryAuthentication.getName();
        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        boolean mfaRequired = evaluateMfaRequirement(user);
        ctx.setMfaRequiredAsPerPolicy(mfaRequired);

        if (!mfaRequired) {
            log.info("MFA not required for user: {}", username);
            ctx.changeState(MfaState.MFA_NOT_REQUIRED);
            return;
        }

        log.info("MFA is required for user: {}", username);

        // 사용자가 등록한 MFA 요소들을 FactorContext에 저장
        Set<AuthType> registeredFactors = parseRegisteredMfaFactorsFromUser(user);
        ctx.setRegisteredMfaFactors(new ArrayList<>(registeredFactors));

        // 다음 진행할 Factor 결정
        determineNextFactorToProcess(ctx);
    }

    private boolean evaluateMfaRequirement(Users user) {
        // MFA 필요 여부 평가 로직
        return user.getRoles().equals("ROLE_ADMIN") ||
                (user.getMfaFactors() != null && !user.getMfaFactors().isEmpty());
    }

    @Override
    public void determineNextFactorToProcess(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found. Cannot determine next factor.");
            ctx.changeState(MfaState.NONE);
            return;
        }

        AuthType nextFactorType = determineNextFactorInternal(
                ctx.getRegisteredMfaFactors(),
                ctx.getCompletedFactors(),
                mfaFlowConfig.getStepConfigs()
        );

        if (nextFactorType != null) {
            processNextFactor(ctx, nextFactorType, mfaFlowConfig);
        } else {
            checkAllFactorsCompleted(ctx, mfaFlowConfig);
        }
    }

    private void processNextFactor(FactorContext ctx, AuthType nextFactorType,
                                   AuthenticationFlowConfig mfaFlowConfig) {
        Optional<AuthenticationStepConfig> nextStepConfigOpt = findNextStepConfig(
                mfaFlowConfig, nextFactorType, ctx
        );

        if (nextStepConfigOpt.isPresent()) {
            AuthenticationStepConfig nextStep = nextStepConfigOpt.get();
            ctx.setCurrentProcessingFactor(nextFactorType);
            ctx.setCurrentStepId(nextStep.getStepId());
            ctx.setCurrentFactorOptions(mfaFlowConfig.getRegisteredFactorOptions().get(nextFactorType));
            ctx.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);

            log.info("Next MFA factor for user {}: Type={}, StepId={}",
                    ctx.getUsername(), nextFactorType, nextStep.getStepId());
        } else {
            log.warn("Next factor type {} determined, but no corresponding uncompleted step config found for user {}",
                    nextFactorType, ctx.getUsername());
            checkAllFactorsCompleted(ctx, mfaFlowConfig);
        }
    }

    private Optional<AuthenticationStepConfig> findNextStepConfig(
            AuthenticationFlowConfig flowConfig, AuthType factorType, FactorContext ctx) {
        return flowConfig.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()) &&
                        !ctx.isFactorCompleted(step.getStepId()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }

    public void checkAllFactorsCompleted(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(ctx, "FactorContext cannot be null");
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null for MFA flow");

        if (!AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName())) {
            log.warn("checkAllFactorsCompleted called with a non-MFA flow config: {}",
                    mfaFlowConfig.getTypeName());
            return;
        }

        List<AuthenticationStepConfig> requiredSteps = getRequiredSteps(mfaFlowConfig);

        if (requiredSteps.isEmpty()) {
            log.warn("MFA flow '{}' for user '{}' has no required steps defined. Marking as fully completed by default.",
                    mfaFlowConfig.getTypeName(), ctx.getUsername());
            ctx.changeState(MfaState.ALL_FACTORS_COMPLETED);
            return;
        }

        CompletionStatus status = evaluateCompletionStatus(ctx, requiredSteps);
        updateContextState(ctx, status, mfaFlowConfig);
    }

    private List<AuthenticationStepConfig> getRequiredSteps(AuthenticationFlowConfig flowConfig) {
        return flowConfig.getStepConfigs().stream()
                .filter(AuthenticationStepConfig::isRequired)
                .collect(Collectors.toList());
    }

    private CompletionStatus evaluateCompletionStatus(FactorContext ctx,
                                                      List<AuthenticationStepConfig> requiredSteps) {
        Set<String> completedRequiredStepIds = new HashSet<>();
        List<String> missingRequiredStepIds = new ArrayList<>();

        for (AuthenticationStepConfig requiredStep : requiredSteps) {
            String requiredStepId = requiredStep.getStepId();

            if (!StringUtils.hasText(requiredStepId)) {
                log.error("Required step with missing or empty stepId found");
                continue;
            }

            if (isStepCompleted(ctx, requiredStepId)) {
                completedRequiredStepIds.add(requiredStepId);
            } else {
                missingRequiredStepIds.add(requiredStepId);
            }
        }

        boolean allRequiredCompleted = missingRequiredStepIds.isEmpty();

        return new CompletionStatus(allRequiredCompleted, completedRequiredStepIds, missingRequiredStepIds);
    }

    private boolean isStepCompleted(FactorContext ctx, String stepId) {
        return ctx.getCompletedFactors().stream()
                .anyMatch(completedFactor -> stepId.equals(completedFactor.getStepId()));
    }

    private void updateContextState(FactorContext ctx, CompletionStatus status,
                                    AuthenticationFlowConfig flowConfig) {
        if (status.allRequiredCompleted && !ctx.getCompletedFactors().isEmpty()) {
            log.info("All required MFA factors completed for user: {}. MFA flow '{}' fully successful.",
                    ctx.getUsername(), flowConfig.getTypeName());
            ctx.changeState(MfaState.ALL_FACTORS_COMPLETED);
        } else if (ctx.getCurrentState() == MfaState.ALL_FACTORS_COMPLETED) {
            log.debug("User {} in flow '{}' is already in ALL_FACTORS_COMPLETED state.",
                    ctx.getUsername(), flowConfig.getTypeName());
        } else if (!ctx.getRegisteredMfaFactors().isEmpty() && ctx.getCompletedFactors().isEmpty() &&
                ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("No MFA factors completed, but registered factors exist for user: {}. Moving to factor selection.",
                    ctx.getUsername());
            ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
            ctx.clearCurrentFactorProcessingState();
        } else if (ctx.getRegisteredMfaFactors().isEmpty()) {
            log.warn("MFA required for user {} but no MFA factors are registered.", ctx.getUsername());
            ctx.changeState(MfaState.MFA_CONFIGURATION_REQUIRED);
        } else {
            log.info("Not all required MFA factors completed for user: {}. Missing steps: {}",
                    ctx.getUsername(), status.missingRequiredStepIds);
            if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
                ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                ctx.clearCurrentFactorProcessingState();
            }
        }
    }

    @Nullable
    private AuthType determineNextFactorInternal(List<AuthType> registeredFactors,
                                                 List<AuthenticationStepConfig> completedFactorSteps,
                                                 List<AuthenticationStepConfig> flowSteps) {
        if (CollectionUtils.isEmpty(registeredFactors) || CollectionUtils.isEmpty(flowSteps)) {
            return null;
        }

        Set<String> completedStepIds = completedFactorSteps.stream()
                .map(AuthenticationStepConfig::getStepId)
                .collect(Collectors.toSet());

        List<AuthenticationStepConfig> sortedSteps = flowSteps.stream()
                .sorted(Comparator.comparingInt(AuthenticationStepConfig::getOrder))
                .collect(Collectors.toList());

        for (AuthenticationStepConfig stepInFlow : sortedSteps) {
            AuthType factorInOrder = parseAuthType(stepInFlow.getType());

            if (factorInOrder != null &&
                    registeredFactors.contains(factorInOrder) &&
                    !completedStepIds.contains(stepInFlow.getStepId())) {

                log.debug("Next MFA factor determined by policy: {} (StepId: {})",
                        factorInOrder, stepInFlow.getStepId());
                return factorInOrder;
            }
        }

        log.debug("No more MFA factors to process based on policy.");
        return null;
    }

    @Nullable
    private AuthType parseAuthType(String type) {
        try {
            return AuthType.valueOf(type.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid AuthType: {}", type);
            return null;
        }
    }

    @Override
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        Assert.notNull(factorType, "FactorType cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");

        int maxAttempts = 3; // 기본값

        log.debug("Providing retry policy (max attempts: {}) for factor {} (user {}, session {})",
                maxAttempts, factorType, ctx.getUsername(), ctx.getMfaSessionId());

        return new RetryPolicy(maxAttempts);
    }

    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");

        if (ctx != null && !CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return ctx.getRegisteredMfaFactors().contains(factorType);
        }

        Optional<Users> userOptional = userRepository.findByUsername(username);
        if (userOptional.isEmpty()) {
            log.warn("User not found for MFA availability check: {}", username);
            return false;
        }

        Users user = userOptional.get();
        return parseRegisteredMfaFactorsFromUser(user).contains(factorType);
    }

    @Override
    public RetryPolicy getRetryPolicy(FactorContext factorContext, AuthenticationStepConfig step) {
        return new RetryPolicy(3);
    }

    private Set<AuthType> parseRegisteredMfaFactorsFromUser(Users user) {
        if (user == null || !StringUtils.hasText(user.getMfaFactors())) {
            return Collections.emptySet();
        }

        try {
            return Arrays.stream(user.getMfaFactors().split(","))
                    .map(String::trim)
                    .map(this::parseAuthTypeSafely)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            log.error("Error parsing MFA factors for user {}: {}", user.getUsername(), e.getMessage());
            return Collections.emptySet();
        }
    }

    @Nullable
    private AuthType parseAuthTypeSafely(String s) {
        try {
            return AuthType.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid MFA factor string: {}", s);
            return null;
        }
    }

    public List<AuthType> getRegisteredMfaFactorsForUser(String username) {
        if (!StringUtils.hasText(username)) {
            return Collections.emptyList();
        }

        return new ArrayList<>(userRepository.findByUsername(username)
                .map(this::parseRegisteredMfaFactorsFromUser)
                .orElse(Collections.emptySet()));
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig() {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                return platformConfig.getFlows().stream()
                        .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElseGet(() -> {
                            log.warn("DefaultMfaPolicyProvider: No AuthenticationFlowConfig found with typeName: MFA");
                            return null;
                        });
            }
        } catch (Exception e) {
            log.warn("DefaultMfaPolicyProvider: Error retrieving PlatformConfig or MFA flow configuration: {}",
                    e.getMessage());
        }
        return null;
    }

    // 내부 클래스 - 완료 상태 정보
    private static class CompletionStatus {
        final boolean allRequiredCompleted;
        final Set<String> completedRequiredStepIds;
        final List<String> missingRequiredStepIds;

        CompletionStatus(boolean allRequiredCompleted, Set<String> completedRequiredStepIds,
                         List<String> missingRequiredStepIds) {
            this.allRequiredCompleted = allRequiredCompleted;
            this.completedRequiredStepIds = completedRequiredStepIds;
            this.missingRequiredStepIds = missingRequiredStepIds;
        }
    }
}