package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 완전 일원화된 DefaultMfaPolicyProvider
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - 모든 상태 변경은 State Machine을 통해서만
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    private final UserRepository userRepository;
    private final ApplicationContext applicationContext;
    // ContextPersistence 완전 제거
    private final MfaStateMachineService stateMachineService; // State Machine Service만 사용
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    /**
     * 완전 일원화: MFA 요구사항 평가 및 초기 단계 결정
     * - State Machine을 통해서만 상태 저장
     */
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

        HttpServletRequest request = getCurrentRequest();

        if (!mfaRequired) {
            log.info("MFA not required for user: {}", username);

            // State Machine에만 저장 (일원화)
            ctx.setMfaRequiredAsPerPolicy(false);
            stateMachineService.saveFactorContext(ctx);

            // State Machine에 이벤트 전송
            if (request != null) {
                stateMachineIntegrator.sendEvent(MfaEvent.MFA_NOT_REQUIRED, ctx, request);
            }
            return;
        }

        log.info("MFA is required for user: {}", username);

        // 사용자가 등록한 MFA 요소들을 FactorContext에 저장
        Set<AuthType> registeredFactors = parseRegisteredMfaFactorsFromUser(user);
        ctx.setAttribute("registeredMfaFactors", new ArrayList<>(registeredFactors));
        ctx.setMfaRequiredAsPerPolicy(true);

        // State Machine에만 저장 (일원화)
        stateMachineService.saveFactorContext(ctx);

        if (registeredFactors.isEmpty()) {
            log.warn("MFA required but no factors registered for user: {}", username);

            if (request != null) {
                stateMachineIntegrator.sendEvent(MfaEvent.MFA_CONFIGURATION_REQUIRED, ctx, request);
            }
            return;
        }

        // State Machine이 다음 팩터를 결정하도록 이벤트 전송
        if (request != null) {
            stateMachineIntegrator.sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request);
        }
    }

    /**
     * 완전 일원화: 다음 팩터 결정
     * - State Machine에서 최신 상태 조회
     * - State Machine을 통해서만 상태 저장
     */
    @Override
    public void determineNextFactorToProcess(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        String sessionId = ctx.getMfaSessionId();

        // State Machine에서 최신 컨텍스트 동기화 (일원화)
        FactorContext latestContext = stateMachineService.getFactorContext(sessionId);
        if (latestContext != null) {
            syncContextFromStateMachine(ctx, latestContext);
        }

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found. Cannot determine next factor.");
            return;
        }

        @SuppressWarnings("unchecked")
        List<AuthType> registeredFactors = (List<AuthType>) ctx.getAttribute("registeredMfaFactors");
        if (registeredFactors == null) {
            registeredFactors = new ArrayList<>();
        }

        AuthType nextFactorType = determineNextFactorInternal(
                registeredFactors,
                ctx.getCompletedFactors(),
                mfaFlowConfig.getStepConfigs()
        );

        if (nextFactorType != null) {
            Optional<AuthenticationStepConfig> nextStepConfigOpt = findNextStepConfig(
                    mfaFlowConfig, nextFactorType, ctx
            );

            if (nextStepConfigOpt.isPresent()) {
                AuthenticationStepConfig nextStep = nextStepConfigOpt.get();

                // 컨텍스트 업데이트
                ctx.setCurrentProcessingFactor(nextFactorType);
                ctx.setCurrentStepId(nextStep.getStepId());
                ctx.setCurrentFactorOptions(mfaFlowConfig.getRegisteredFactorOptions().get(nextFactorType));

                // State Machine에만 저장 (일원화)
                stateMachineService.saveFactorContext(ctx);

                log.info("Next MFA factor determined for user {}: Type={}, StepId={}",
                        ctx.getUsername(), nextFactorType, nextStep.getStepId());

                // State Machine에 이벤트 전송
                HttpServletRequest request = getCurrentRequest();
                if (request != null && stateMachineIntegrator != null) {
                    stateMachineIntegrator.sendEvent(MfaEvent.FACTOR_SELECTED, ctx, request);
                }
            }
        } else {
            checkAllFactorsCompleted(ctx, mfaFlowConfig);
        }
    }

    /**
     * 완전 일원화: 모든 팩터 완료 확인
     * - State Machine에서 최신 상태 조회
     * - State Machine을 통해서만 상태 저장
     */
    public void checkAllFactorsCompleted(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(ctx, "FactorContext cannot be null");
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null for MFA flow");

        if (!AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName())) {
            log.warn("checkAllFactorsCompleted called with a non-MFA flow config: {}",
                    mfaFlowConfig.getTypeName());
            return;
        }

        String sessionId = ctx.getMfaSessionId();

        // State Machine에서 최신 상태 동기화 (일원화)
        FactorContext latestContext = stateMachineService.getFactorContext(sessionId);
        if (latestContext != null) {
            syncContextFromStateMachine(ctx, latestContext);
        }

        List<AuthenticationStepConfig> requiredSteps = getRequiredSteps(mfaFlowConfig);

        if (requiredSteps.isEmpty()) {
            log.warn("MFA flow '{}' for user '{}' has no required steps defined. Marking as fully completed by default.",
                    mfaFlowConfig.getTypeName(), ctx.getUsername());

            // State Machine에만 저장 (일원화)
            stateMachineService.saveFactorContext(ctx);

            HttpServletRequest request = getCurrentRequest();
            if (request != null && stateMachineIntegrator != null) {
                stateMachineIntegrator.sendEvent(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED, ctx, request);
            }
            return;
        }

        CompletionStatus status = evaluateCompletionStatus(ctx, requiredSteps);

        // State Machine에만 저장 (일원화)
        stateMachineService.saveFactorContext(ctx);

        HttpServletRequest request = getCurrentRequest();

        if (status.allRequiredCompleted && !ctx.getCompletedFactors().isEmpty()) {
            log.info("All required MFA factors completed for user: {}. MFA flow '{}' fully successful.",
                    ctx.getUsername(), mfaFlowConfig.getTypeName());

            if (request != null && stateMachineIntegrator != null) {
                stateMachineIntegrator.sendEvent(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED, ctx, request);
            }
        } else if (!ctx.getRegisteredMfaFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
            log.info("No MFA factors completed, but registered factors exist for user: {}. Moving to factor selection.",
                    ctx.getUsername());

            if (request != null && stateMachineIntegrator != null) {
                stateMachineIntegrator.sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request);
            }
        } else if (ctx.getRegisteredMfaFactors().isEmpty()) {
            log.warn("MFA required for user {} but no MFA factors are registered.", ctx.getUsername());

            if (request != null && stateMachineIntegrator != null) {
                stateMachineIntegrator.sendEvent(MfaEvent.MFA_CONFIGURATION_REQUIRED, ctx, request);
            }
        } else {
            log.info("Not all required MFA factors completed for user: {}. Missing steps: {}",
                    ctx.getUsername(), status.missingRequiredStepIds);

            if (request != null && stateMachineIntegrator != null) {
                stateMachineIntegrator.sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request);
            }
        }
    }

    /**
     * 완전 일원화: State Machine에서 컨텍스트 동기화
     * - State Machine이 진실의 원천
     */
    private void syncContextFromStateMachine(FactorContext target, FactorContext source) {
        if (target.getCurrentState() != source.getCurrentState()) {
            target.changeState(source.getCurrentState());
        }

        // 버전 동기화
        while (target.getVersion() < source.getVersion()) {
            target.incrementVersion();
        }

        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setCurrentFactorOptions(source.getCurrentFactorOptions());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

        // 중요한 속성들 동기화
        source.getAttributes().forEach((key, value) -> {
            if (isImportantAttribute(key)) {
                target.setAttribute(key, value);
            }
        });

        log.debug("Context synchronized from State Machine: sessionId={}, version={}, state={}",
                target.getMfaSessionId(), target.getVersion(), target.getCurrentState());
    }

    private boolean isImportantAttribute(String key) {
        return "registeredMfaFactors".equals(key) ||
                "deviceId".equals(key) ||
                "clientIp".equals(key) ||
                "userAgent".equals(key) ||
                "loginTimestamp".equals(key) ||
                key.startsWith("challenge") ||
                key.startsWith("verification");
    }

    /**
     * 완전 일원화: 팩터 가용성 확인
     * - State Machine에서 최신 상태 조회
     */
    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");

        // State Machine에서 최신 컨텍스트 확인 (일원화)
        if (ctx != null) {
            String sessionId = ctx.getMfaSessionId();
            FactorContext latestContext = stateMachineService.getFactorContext(sessionId);
            if (latestContext != null) {
                @SuppressWarnings("unchecked")
                List<AuthType> registeredFactors = (List<AuthType>) latestContext.getAttribute("registeredMfaFactors");
                if (!CollectionUtils.isEmpty(registeredFactors)) {
                    return registeredFactors.contains(factorType);
                }
            }
        }

        // DB에서 확인 (Fallback)
        Optional<Users> userOptional = userRepository.findByUsername(username);
        if (userOptional.isEmpty()) {
            log.warn("User not found for MFA availability check: {}", username);
            return false;
        }

        Users user = userOptional.get();
        return parseRegisteredMfaFactorsFromUser(user).contains(factorType);
    }

    // === 기존 메서드들 유지 (변경 없음) ===

    @Override
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        Assert.notNull(factorType, "FactorType cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");

        int maxAttempts = switch (factorType) {
            case OTT -> 5;
            case PASSKEY -> 3;
            default -> 3;
        };

        log.debug("Providing retry policy (max attempts: {}) for factor {} (user {}, session {})",
                maxAttempts, factorType, ctx.getUsername(), ctx.getMfaSessionId());

        return new RetryPolicy(maxAttempts);
    }

    @Override
    public RetryPolicy getRetryPolicy(FactorContext factorContext, AuthenticationStepConfig step) {
        if (step.getOptions() != null) {
            Integer maxRetries = (Integer) step.getOptions().get("maxRetries");
            if (maxRetries != null) {
                return new RetryPolicy(maxRetries);
            }
        }
        return new RetryPolicy(3);
    }

    @Override
    public Integer getRequiredFactorCount(String userId, String flowType) {
        Users user = userRepository.findByUsername(userId).orElse(null);

        if (user != null) {
            if ("ROLE_ADMIN".equals(user.getRoles())) {
                return 2;
            }

            if (user.getRegisteredMfaFactors() != null) {
                return user.getRegisteredMfaFactors().size();
            }
        }

        return switch (flowType.toLowerCase()) {
            case "mfa" -> 2;
            case "mfa-stepup" -> 1;
            case "mfa-transactional" -> 1;
            default -> 1;
        };
    }

    // === 내부 유틸리티 메서드들 (변경 없음) ===

    private boolean evaluateMfaRequirement(Users user) {
        if ("ROLE_ADMIN".equals(user.getRoles())) {
            return true;
        }

        if (user.getMfaFactors() != null && !user.getMfaFactors().isEmpty()) {
            return true;
        }

        return false;
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

    private Optional<AuthenticationStepConfig> findNextStepConfig(
            AuthenticationFlowConfig flowConfig, AuthType factorType, FactorContext ctx) {
        return flowConfig.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()) &&
                        !ctx.isFactorCompleted(step.getStepId()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
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

    private Set<AuthType> parseRegisteredMfaFactorsFromUser(Users user) {
        if (user == null || user.getMfaFactors() == null || user.getMfaFactors().isEmpty()) {
            return Collections.emptySet();
        }

        try {
            return user.getMfaFactors().stream()
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

    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attrs = (ServletRequestAttributes)
                RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest() : null;
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