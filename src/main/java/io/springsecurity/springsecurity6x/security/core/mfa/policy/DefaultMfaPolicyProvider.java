package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.domain.UserDto;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.FactorSelectionType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
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
 * 개선사항:
 * - 이벤트 처리 표준화: 1) 상태 업데이트 2) 저장 3) 이벤트 전송 순서 보장
 * - 예외 처리 강화: 각 단계별 실패 처리 로직 추가
 * - 성능 최적화: 불필요한 동기화 호출 최소화
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    private final UserRepository userRepository;
    private final ApplicationContext applicationContext;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final AuthContextProperties properties;

    /**
     * ✅ 개선: MFA 요구사항 평가 및 초기 단계 결정 - 동기화 강화
     */
    @Override
    public void evaluateMfaRequirementAndDetermineInitialStep(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        String username = ctx.getUsername();
        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        boolean mfaRequired = evaluateMfaRequirement(user);
        HttpServletRequest request = getCurrentRequest();

        if (!mfaRequired) {
            log.info("MFA not required for user: {}", username);

            // 개선: 표준 패턴 적용 - 동기화 포함
            boolean success = executeStandardEventPattern(
                    ctx,
                    () -> ctx.setMfaRequiredAsPerPolicy(false), // 상태 업데이트
                    MfaEvent.MFA_NOT_REQUIRED,
                    request,
                    "MFA_NOT_REQUIRED processing for user: " + username
            );

            if (!success) {
                handleEventProcessingFailure(ctx, "MFA_NOT_REQUIRED", username);
            }
            return;
        }

        log.info("MFA is required for user: {}", username);

        // 사용자가 등록한 MFA 요소들 확인
        Set<AuthType> registeredFactors = parseRegisteredMfaFactorsFromUser(user);

        // 필요한 팩터 수 확인
        int requiredCount = getRequiredFactorCount(username, ctx.getFlowTypeName());

        // 동기화를 포함한 표준 패턴으로 MFA 필요 상태 설정
        boolean success = executeStandardEventPattern(
                ctx,
                () -> {
                    ctx.setAttribute("registeredMfaFactors", new ArrayList<>(registeredFactors));
                    ctx.setMfaRequiredAsPerPolicy(true);
                    ctx.setAttribute("requiredFactorCount", requiredCount);
                    ctx.setAttribute("registeredFactorCount", registeredFactors.size());
                },
                null, // 이벤트는 조건에 따라 결정
                request,
                "MFA setup for user: " + username
        );

        if (!success) {
            handleEventProcessingFailure(ctx, "MFA_SETUP", username);
            return;
        }

        // 등록된 팩터에 따른 이벤트 결정 및 전송 (동기화 포함)
        if (registeredFactors.isEmpty()|| registeredFactors.size() < requiredCount) {

            // 팩터가 없거나 부족한 경우
            if (!registeredFactors.isEmpty()) {
                ctx.setAttribute("additionalFactorsNeeded", requiredCount - registeredFactors.size());
                log.info("User {} has {} factors but needs {}", username, registeredFactors.size(), requiredCount);
            }

            sendEventWithSync(MfaEvent.MFA_CONFIGURATION_REQUIRED, ctx, request,
                    String.format("MFA_CONFIGURATION_REQUIRED for user: %s (has %d, needs %d)",
                            username, registeredFactors.size(), requiredCount));
        } else {

            if(properties.getFactorSelectionType() == FactorSelectionType.AUTO){

                boolean autoSelected = autoSelectInitialFactor(ctx, registeredFactors);

                if (autoSelected) {
                    // 바로 챌린지 시작
                    sendEventWithSync(MfaEvent.INITIATE_CHALLENGE_AUTO, ctx, request,
                            "INITIATE_CHALLENGE_AUTO with auto-selected " +
                                    ctx.getCurrentProcessingFactor() + " for user: " + username);
                }else {
                    // 자동 선택 실패 시 수동 선택
                    sendEventWithSync(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request,
                            "Fallback to MFA_REQUIRED_SELECT_FACTOR for user: " + username);
                }

            }else{
                sendEventWithSync(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request,
                        "INITIATE_CHALLENGE for user: " + username);

            }
        }
    }

    /**
     * 초기 MFA 팩터 자동 선택 (첫 번째 팩터 선택용)
     * @return 자동 선택 성공 여부
     */
    private boolean autoSelectInitialFactor(FactorContext ctx, Set<AuthType> registeredFactors) {
        if (registeredFactors.isEmpty()) {
            return false;
        }

        AuthType selectedFactor = null;

        // 1. 단일 팩터인 경우
        if (registeredFactors.size() == 1) {
            selectedFactor = registeredFactors.iterator().next();
            log.info("Auto-selecting single registered factor: {}", selectedFactor);
        }

        // 2. 사용자 선호도 기반
        if (selectedFactor == null) {
            selectedFactor = getUserPreferredFactor(ctx.getUsername(), registeredFactors);
        }

        // 3. 시스템 우선순위 기반
        if (selectedFactor == null) {
            selectedFactor = getSystemPriorityFactor(registeredFactors);
        }

        if (selectedFactor != null) {
            // 팩터 설정
            AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
            Optional<AuthenticationStepConfig> stepConfig = findNextStepConfig(mfaFlowConfig, selectedFactor, ctx);

            if (stepConfig.isPresent()) {
                ctx.setCurrentProcessingFactor(selectedFactor);
                ctx.setCurrentStepId(stepConfig.get().getStepId());
                ctx.setAttribute("autoSelectedInitialFactor", true);

                // State Machine에 저장
                stateMachineIntegrator.saveFactorContext(ctx);

                log.info("Initial factor auto-selected: {} for user: {}",
                        selectedFactor, ctx.getUsername());
                return true;
            }
        }

        return false;
    }

    /**
     * 사용자 선호 팩터 조회
     */
    private AuthType getUserPreferredFactor(String username, Set<AuthType> available) {
        Users user = userRepository.findByUsername(username).orElse(null);
        if (user != null) {
            String preferred = user.getPreferredMfaFactor(); // 자동으로 fallback 처리
            if (preferred != null) {
                try {
                    AuthType preferredType = AuthType.valueOf(preferred);
                    if (available.contains(preferredType)) {
                        log.debug("Using user preferred factor: {}", preferredType);
                        return preferredType;
                    }
                } catch (IllegalArgumentException e) {
                    log.debug("Invalid preferred factor: {}", preferred);
                }
            }
        }
        return null;
    }

    /**
     * 시스템 우선순위 기반 팩터 선택
     */
    private AuthType getSystemPriorityFactor(Set<AuthType> available) {
        // 시스템 정의 우선순위
        List<AuthType> priority = Arrays.asList(
                AuthType.PASSKEY,    // 가장 편리하고 안전
                AuthType.OTT        // 이메일 기반
        );

        for (AuthType factor : priority) {
            if (available.contains(factor)) {
                log.debug("Using system priority factor: {}", factor);
                return factor;
            }
        }

        // 우선순위에 없으면 첫 번째 것 선택
        return available.iterator().next();
    }

    /**
     * ✅ 새로운 메서드: 이벤트 전송과 동기화를 함께 수행
     */
    private boolean sendEventWithSync(MfaEvent event, FactorContext ctx, HttpServletRequest request, String context) {
        boolean success = sendEventSafely(event, ctx, request, context);

        if (success && request != null) {
            try {
                // 이벤트 전송 후 동기화
                stateMachineIntegrator.refreshFactorContextFromStateMachine(ctx, request);

                log.debug("Context synchronized after event {} for session: {}", event, ctx.getMfaSessionId());
            } catch (Exception e) {
                log.warn("Failed to sync after event {} for session: {}", event, ctx.getMfaSessionId(), e);
                // 동기화 실패는 경고만 로깅하고 계속 진행
            }
        }

        return success;
    }

    /**
     * 다음 팩터 결정 - 동기화 최적화 적용
     */
    @Override
    public void determineNextFactorToProcess(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        String sessionId = ctx.getMfaSessionId();
        syncWithStateMachineIfNeeded(ctx);

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found. Cannot determine next factor.");
            handleConfigurationError(ctx, "MFA flow configuration not found");
            return;
        }

        List<AuthType> registeredFactors = Arrays.stream(new String[]{(String)ctx.getAttribute("registeredMfaFactors")})
                .flatMap(s -> Arrays.stream(s.split(",")))
                .map(String::trim)
                .map(AuthType::valueOf)
                .toList();

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

                // 표준 패턴으로 다음 팩터 설정 - 동기화 포함
                boolean success = executeStandardEventPattern(
                        ctx,
                        () -> {
                            ctx.setCurrentProcessingFactor(nextFactorType);
                            ctx.setCurrentStepId(nextStep.getStepId());
                        },
                        MfaEvent.FACTOR_SELECTED,
                        getCurrentRequest(),
                        "Next factor determined: " + nextFactorType + " for session: " + sessionId
                );

                if (success) {
                    log.info("Next MFA factor determined for user {}: Type={}, StepId={}",
                            ctx.getUsername(), nextFactorType, nextStep.getStepId());
                } else {
                    handleEventProcessingFailure(ctx, "FACTOR_SELECTION", ctx.getUsername());
                }
            }
        } else {
            checkAllFactorsCompleted(ctx, mfaFlowConfig);
        }
    }

    /**
     * 모든 팩터 완료 확인 - 동기화 최적화
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

        // 개선: 필요한 경우에만 동기화
        syncWithStateMachineIfNeeded(ctx);

        List<AuthenticationStepConfig> requiredSteps = getRequiredSteps(mfaFlowConfig);

        if (requiredSteps.isEmpty()) {
            log.warn("MFA flow '{}' for user '{}' has no required steps defined. Marking as fully completed by default.",
                    mfaFlowConfig.getTypeName(), ctx.getUsername());

            sendEventWithSync(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED, ctx, getCurrentRequest(),
                    "All factors completed (no required steps) for user: " + ctx.getUsername());
            return;
        }

        CompletionStatus status = evaluateCompletionStatus(ctx, requiredSteps);
        HttpServletRequest request = getCurrentRequest();

        // 완료 상태에 따른 이벤트 전송 (동기화 포함)
        if (status.allRequiredCompleted && !ctx.getCompletedFactors().isEmpty()) {
            log.info("All required MFA factors completed for user: {}. MFA flow '{}' fully successful.",
                    ctx.getUsername(), mfaFlowConfig.getTypeName());

            sendEventWithSync(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED, ctx, request,
                    "All required factors completed for user: " + ctx.getUsername());

        } else if (!ctx.getRegisteredMfaFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
            log.info("No MFA factors completed, but registered factors exist for user: {}. Moving to factor selection.",
                    ctx.getUsername());

            sendEventWithSync(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request,
                    "Moving to factor selection for user: " + ctx.getUsername());

        } else if (ctx.getRegisteredMfaFactors().isEmpty()) {
            log.warn("MFA required for user {} but no MFA factors are registered.", ctx.getUsername());

            sendEventWithSync(MfaEvent.MFA_CONFIGURATION_REQUIRED, ctx, request,
                    "MFA configuration required for user: " + ctx.getUsername());

        } else {
            log.info("Not all required MFA factors completed for user: {}. Missing steps: {}",
                    ctx.getUsername(), status.missingRequiredStepIds);

            sendEventWithSync(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request,
                    "Additional factors required for user: " + ctx.getUsername());
        }
    }

    // === 개선된 헬퍼 메서드들 ===

    /**
     * 개선: 표준화된 이벤트 처리 패턴
     * 1) 컨텍스트 상태 업데이트 2) State Machine 저장 3) 이벤트 전송 4) 동기화
     */
    private boolean executeStandardEventPattern(FactorContext ctx,
                                                Runnable contextUpdater,
                                                @Nullable MfaEvent event,
                                                HttpServletRequest request,
                                                String operationDescription) {
        try {
            log.debug("Executing standard event pattern: {}", operationDescription);

            // 1) 컨텍스트 업데이트
            if (contextUpdater != null) {
                contextUpdater.run();
            }

            // 2) State Machine에 저장
            stateMachineIntegrator.saveFactorContext(ctx);

            // 3) 이벤트 전송 (있는 경우)
            if (event != null && request != null) {
                boolean accepted = stateMachineIntegrator.sendEvent(event, ctx, request);
                if (!accepted) {
                    log.error("Event {} was not accepted for session: {} during: {}",
                            event, ctx.getMfaSessionId(), operationDescription);
                    return false;
                }

                // 추가: 이벤트 전송 후 State Machine과 동기화
                try {
                    stateMachineIntegrator.refreshFactorContextFromStateMachine(ctx, request);
                    log.debug("Context synchronized after event {} for session: {}",
                            event, ctx.getMfaSessionId());
                } catch (Exception syncException) {
                    log.error("Failed to sync context after event {} for session: {}",
                            event, ctx.getMfaSessionId(), syncException);
                    // 동기화 실패는 경고만 하고 계속 진행
                }
            }

            log.debug("Standard event pattern completed successfully: {}", operationDescription);
            return true;

        } catch (Exception e) {
            log.error("Failed to execute standard event pattern: {} for session: {}",
                    operationDescription, ctx.getMfaSessionId(), e);
            return false;
        }
    }

    /**
     * 개선: 안전한 이벤트 전송 - 실패 처리 포함
     */
    private boolean sendEventSafely(MfaEvent event, FactorContext ctx, HttpServletRequest request, String context) {
        if (request == null) {
            log.debug("No HTTP request available for event: {} in context: {}", event, context);
            return true; // request가 없는 것은 정상적인 상황일 수 있음
        }

        try {

            if (event == MfaEvent.FACTOR_SELECTED && ctx.getCurrentProcessingFactor() != null) {
                request.setAttribute("selectedFactor", ctx.getCurrentProcessingFactor().name());
            }

            boolean accepted = stateMachineIntegrator.sendEvent(event, ctx, request);
            if (!accepted) {
                log.error("Event {} rejected in context: {} for session: {}",
                        event, context, ctx.getMfaSessionId());
                handleEventRejection(ctx, event, context);
                return false;
            }

            log.debug("Event {} sent successfully in context: {}", event, context);
            return true;

        } catch (Exception e) {
            log.error("Exception occurred while sending event {} in context: {} for session: {}",
                    event, context, ctx.getMfaSessionId(), e);
            handleEventException(ctx, event, context, e);
            return false;
        }
    }

    /**
     * 개선: 조건부 동기화 - 필요한 경우에만 수행
     */
    private void syncWithStateMachineIfNeeded(FactorContext ctx) {
        // State Machine에서 현재 상태 확인
        MfaState currentStateInSM = stateMachineIntegrator.getCurrentState(ctx.getMfaSessionId());

        // 상태가 다른 경우에만 동기화
        if (ctx.getCurrentState() != currentStateInSM) {
            log.debug("State mismatch detected for session: {}. Context: {}, StateMachine: {}. Syncing...",
                    ctx.getMfaSessionId(), ctx.getCurrentState(), currentStateInSM);

            FactorContext latestContext = stateMachineIntegrator.loadFactorContext(ctx.getMfaSessionId());
            if (latestContext != null) {
                syncContextFromStateMachine(ctx, latestContext);
            }
        }
    }

    /**
     * 개선: 이벤트 처리 실패 핸들링
     */
    private void handleEventProcessingFailure(FactorContext ctx, String operation, String username) {
        log.error("Event processing failed for operation: {} for user: {}", operation, username);

        // 시스템 오류 상태로 설정
        ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
        ctx.setLastError("Event processing failed: " + operation);

        // 저장만 하고 이벤트는 전송하지 않음 (무한 루프 방지)
        stateMachineIntegrator.saveFactorContext(ctx);
    }

    /**
     * 개선: 설정 오류 처리
     */
    private void handleConfigurationError(FactorContext ctx, String errorMessage) {
        log.error("Configuration error for session: {} - {}", ctx.getMfaSessionId(), errorMessage);

        ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
        ctx.setLastError("Configuration error: " + errorMessage);
        stateMachineIntegrator.saveFactorContext(ctx);
    }

    /**
     * 개선: 이벤트 거부 시 처리
     */
    private void handleEventRejection(FactorContext ctx, MfaEvent event, String context) {
        log.warn("Handling event rejection for event: {} in context: {} for session: {}",
                event, context, ctx.getMfaSessionId());

        // 현재 상태에 따른 적절한 처리
        MfaState currentState = ctx.getCurrentState();
        if (!currentState.isTerminal()) {
            // 터미널 상태가 아니면 에러 정보만 기록
            ctx.setLastError("Event rejected: " + event + " in context: " + context);
            stateMachineIntegrator.saveFactorContext(ctx);
        }
    }

    /**
     * 개선: 이벤트 예외 처리
     */
    private void handleEventException(FactorContext ctx, MfaEvent event, String context, Exception e) {
        log.error("Exception in event processing for event: {} in context: {} for session: {}",
                event, context, ctx.getMfaSessionId(), e);

        ctx.setLastError("Event exception: " + e.getMessage());
        ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
        stateMachineIntegrator.saveFactorContext(ctx);
    }

    // === 기존 메서드들 (변경 없음) ===

    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");

        if (ctx != null) {
            String sessionId = ctx.getMfaSessionId();
            FactorContext latestContext = stateMachineIntegrator.loadFactorContext(sessionId);
            if (latestContext != null) {
                @SuppressWarnings("unchecked")
                List<AuthType> registeredFactors = (List<AuthType>) latestContext.getAttribute("registeredMfaFactors");
                if (!CollectionUtils.isEmpty(registeredFactors)) {
                    return registeredFactors.contains(factorType);
                }
            }
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

            int baseCount = 1; // 기본값
            return adjustRequiredFactorCount(baseCount, userId, flowType);
        }

        return switch (flowType.toLowerCase()) {
            case "mfa" -> 2;
            case "mfa-stepup" -> 1;
            case "mfa-transactional" -> 1;
            default -> 1;
        };
    }

    // AI 통합을 위한 확장 포인트 (Protected로 오버라이드 가능)
    protected int adjustRequiredFactorCount(int baseCount, String userId, String flowType) {
        // 기본 구현은 그대로 반환
        return baseCount;
    }

    // === 기존 내부 유틸리티 메서드들 (변경 없음) ===

    private boolean evaluateMfaRequirement(Users user) {
        if ("ROLE_ADMIN".equals(user.getRoles())) {
            return true;
        }

        return user.getMfaFactors() != null && !user.getMfaFactors().isEmpty();
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

            if(requiredStep.isPrimary()) continue; // 1차 인증은 제외

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
                .toList();

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

    /**
     * State Machine에서 컨텍스트 동기화
     */
    private void syncContextFromStateMachine(FactorContext target, FactorContext source) {
        if (target.getCurrentState() != source.getCurrentState()) {
            target.changeState(source.getCurrentState());
        }

        while (target.getVersion() < source.getVersion()) {
            target.incrementVersion();
        }

        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

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