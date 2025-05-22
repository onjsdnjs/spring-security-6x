package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
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
    private final ApplicationContext applicationContext; // PlatformConfig를 가져오기 위해 유지

    @Override
    public void evaluateMfaRequirementAndDetermineInitialStep(Authentication primaryAuthentication, FactorContext ctx) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        Assert.isTrue(Objects.equals(primaryAuthentication.getName(), ctx.getUsername()), "Username mismatch in FactorContext and Authentication");

        String username = primaryAuthentication.getName();
        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        // 사용자의 역할 또는 다른 조건에 따라 MFA 필요 여부 결정 (예시)
        boolean mfaRequired = user.getRoles().equals("ROLE_ADMIN") ||
                (user.getMfaFactors() != null && !user.getMfaFactors().isEmpty()); // MFA 요소가 하나라도 등록되어 있으면 MFA 필요

        ctx.setMfaRequiredAsPerPolicy(mfaRequired);

        if (!mfaRequired) {
            log.info("MFA not required for user: {}", username);
            ctx.changeState(MfaState.MFA_NOT_REQUIRED);
            return;
        }

        log.info("MFA is required for user: {}", username);
        // 사용자가 등록한 MFA 요소들을 FactorContext에 저장
        Set<AuthType> registeredFactors = parseRegisteredMfaFactorsFromUser(user);
        ctx.setRegisteredMfaFactors(new ArrayList<>(registeredFactors)); // EnumSet 대신 ArrayList 사용 (FactorContext의 setRegisteredMfaFactors는 List<AuthType>을 받음)

        // 다음 진행할 Factor 결정
        determineNextFactorToProcess(ctx); // 이 메서드가 ctx의 상태와 currentProcessingFactor 등을 설정
    }

    @Override
    public void determineNextFactorToProcess(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found. Cannot determine next factor.");
            ctx.changeState(MfaState.NONE); // 또는 다른 적절한 에러 상태
            return;
        }

        // 사용자가 등록한 MFA 요소와 MFA 플로우에 정의된 단계를 비교하여 다음에 진행할 단계를 결정
        AuthType nextFactorType = determineNextFactorInternal(ctx.getRegisteredMfaFactors(), ctx.getCompletedFactors(), mfaFlowConfig.getStepConfigs());

        if (nextFactorType != null) {
            Optional<AuthenticationStepConfig> nextStepConfigOpt = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> nextFactorType.name().equalsIgnoreCase(step.getType()) && !ctx.isFactorCompleted(step.getStepId()))
                    .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder)); // 가장 낮은 order의 미완료 스텝

            if (nextStepConfigOpt.isPresent()) {
                AuthenticationStepConfig nextStep = nextStepConfigOpt.get();
                ctx.setCurrentProcessingFactor(nextFactorType);
                ctx.setCurrentStepId(nextStep.getStepId());
                ctx.setCurrentFactorOptions(mfaFlowConfig.getRegisteredFactorOptions().get(nextFactorType));
                ctx.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
                log.info("Next MFA factor for user {}: Type={}, StepId={}", ctx.getUsername(), nextFactorType, nextStep.getStepId());
            } else {
                log.warn("Next factor type {} determined, but no corresponding uncompleted step config found for user {}. Potentially all steps for this factor type are completed or misconfigured.", nextFactorType, ctx.getUsername());
                // 이 경우, 다른 사용 가능한 팩터가 있는지 다시 확인하거나, 모든 팩터 완료로 처리할 수 있음
                // 여기서는 일단 선택 화면으로 유도하거나 완료 처리
                checkAllFactorsCompleted(ctx, mfaFlowConfig);
            }
        } else {
            // 더 이상 진행할 MFA 요소가 없음 (모두 완료했거나, 더 이상 사용 가능한 요소가 없음)
            checkAllFactorsCompleted(ctx, mfaFlowConfig);
        }
    }

    /**
     * MFA 플로우의 모든 필수 단계가 완료되었는지 확인하고, 그에 따라 FactorContext의 상태를 변경합니다.
     * 이 메소드는 MfaFactorProcessingSuccessHandler 또는 MfaContinuationHandler 에서 호출될 수 있습니다.
     *
     * @param ctx           현재 FactorContext
     * @param mfaFlowConfig 현재 MFA 플로우 설정
     */
    public void checkAllFactorsCompleted(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(ctx, "FactorContext cannot be null");
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null for MFA flow");

        if (!AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName())) {
            log.warn("checkAllFactorsCompleted called with a non-MFA flow config: {}", mfaFlowConfig.getTypeName());
            return;
        }

        // MFA 플로우에 정의된 모든 "필수" 단계를 가져옵니다.
        List<AuthenticationStepConfig> requiredSteps = mfaFlowConfig.getStepConfigs().stream()
                .filter(AuthenticationStepConfig::isRequired)
                .toList();

        if (requiredSteps.isEmpty()) {
            log.warn("MFA flow '{}' for user '{}' has no required steps defined. Marking as fully completed by default.",
                    mfaFlowConfig.getTypeName(), ctx.getUsername());
            ctx.changeState(MfaState.MFA_FULLY_COMPLETED);
            return;
        }

        // 완료된 필수 단계를 추적합니다.
        Set<String> completedRequiredStepIds = new HashSet<>();
        List<String> missingRequiredStepIds = new ArrayList<>();

        for (AuthenticationStepConfig requiredStep : requiredSteps) {
            String requiredStepId = requiredStep.getStepId();
            if (!StringUtils.hasText(requiredStepId)) {
                log.error("MFA flow '{}' has a required step with a missing or empty stepId. This step will be ignored in completion check. Step Details: {}",
                        mfaFlowConfig.getTypeName(), requiredStep);
                // 이 경우, 이 단계를 "완료 불가능"으로 간주할지, 아니면 설정을 수정해야 할지 정책 결정 필요.
                // 여기서는 로그만 남기고 다음 단계로 진행 (사실상 이 단계는 무시됨).
                continue;
            }

            boolean currentStepCompleted = ctx.getCompletedFactors().stream()
                    .anyMatch(completedFactor -> requiredStepId.equals(completedFactor.getStepId()));

            if (currentStepCompleted) {
                completedRequiredStepIds.add(requiredStepId);
            } else {
                missingRequiredStepIds.add(requiredStepId);
            }
        }

        log.debug("MFA completion check for user '{}', flow '{}': Required steps: {}, Completed required steps: {}, Missing required steps: {}",
                ctx.getUsername(), mfaFlowConfig.getTypeName(),
                requiredSteps.stream().map(AuthenticationStepConfig::getStepId).collect(Collectors.toList()),
                completedRequiredStepIds,
                missingRequiredStepIds);

        // 모든 필수 단계가 완료되었는지 확인 (missingRequiredStepIds가 비어있는지 확인)
        boolean allRequiredCompleted = missingRequiredStepIds.isEmpty();

        if (allRequiredCompleted && !ctx.getCompletedFactors().isEmpty()) {
            // 모든 필수 단계가 완료되었고, 실제로 하나 이상의 요소가 완료된 경우
            log.info("All required MFA factors completed for user: {}. MFA flow '{}' fully successful.", ctx.getUsername(), mfaFlowConfig.getTypeName());
            ctx.changeState(MfaState.MFA_FULLY_COMPLETED);
        } else if (ctx.getCurrentState() == MfaState.MFA_FULLY_COMPLETED) {
            // 이미 MFA_FULLY_COMPLETED 상태라면 더 이상 상태를 변경하지 않음 (예: 중복 호출 방지)
            log.debug("User {} in flow '{}' is already in MFA_FULLY_COMPLETED state.", ctx.getUsername(), mfaFlowConfig.getTypeName());
        } else if (!ctx.getRegisteredMfaFactors().isEmpty() && ctx.getCompletedFactors().isEmpty() && ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            // 등록된 MFA 요소가 있지만, 아무것도 완료하지 못했고, 현재 선택 대기 상태가 아니라면 선택 화면으로.
            log.info("No MFA factors completed, but registered factors exist for user: {}. Moving to factor selection for flow '{}'.", ctx.getUsername(), mfaFlowConfig.getTypeName());
            ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
            ctx.clearCurrentFactorProcessingState(); // 현재 처리 중인 팩터 정보 초기화
        } else if (ctx.getRegisteredMfaFactors().isEmpty()) {
            // 사용자에게 등록된 MFA 요소가 없는 경우
            log.warn("MFA required for user {} in flow '{}', but no MFA factors are registered by the user. Setting state to MFA_CONFIGURATION_REQUIRED.",
                    ctx.getUsername(), mfaFlowConfig.getTypeName());
            ctx.changeState(MfaState.MFA_CONFIGURATION_REQUIRED);
        } else {
            // 모든 필수 요소가 완료되지 않았거나, 처리할 다음 요소가 있는 경우 (또는 선택해야 하는 경우)
            log.info("Not all required MFA factors completed for user: {} in flow '{}', or awaiting next action. Current state: {}. Missing steps: {}",
                    ctx.getUsername(), mfaFlowConfig.getTypeName(), ctx.getCurrentState(), missingRequiredStepIds);
            // 이미 완료된 상태가 아니고, 선택 대기 상태가 아니라면, 다음 요소 선택 대기 상태로 변경하는 것이 안전할 수 있음
            if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
                ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                ctx.clearCurrentFactorProcessingState();
            }
        }
    }


    /**
     * 다음에 처리할 MFA 요소를 결정합니다.
     * 사용자가 등록한 MFA 요소와 이미 완료한 MFA 요소를 기반으로,
     * MFA 플로우 설정에 정의된 순서대로 다음 요소를 찾습니다.
     */
    @Nullable
    private AuthType determineNextFactorInternal(List<AuthType> registeredFactors, List<AuthenticationStepConfig> completedFactorSteps, List<AuthenticationStepConfig> flowSteps) {
        if (CollectionUtils.isEmpty(registeredFactors) || CollectionUtils.isEmpty(flowSteps)) {
            return null;
        }

        Set<String> completedStepIds = completedFactorSteps.stream()
                .map(AuthenticationStepConfig::getStepId)
                .collect(Collectors.toSet());

        // 플로우에 정의된 순서대로, 사용자가 등록했고 아직 완료하지 않은 첫 번째 팩터를 찾음
        for (AuthenticationStepConfig stepInFlow : flowSteps.stream().sorted(Comparator.comparingInt(AuthenticationStepConfig::getOrder)).toList()) {
            AuthType factorInOrder;
            try {
                factorInOrder = AuthType.valueOf(stepInFlow.getType().toUpperCase());
            } catch (IllegalArgumentException e) {
                log.warn("Invalid AuthType in flowSteps: {}", stepInFlow.getType());
                continue;
            }

            if (registeredFactors.contains(factorInOrder) && !completedStepIds.contains(stepInFlow.getStepId())) {
                log.debug("Next MFA factor determined by policy: {} (StepId: {})", factorInOrder, stepInFlow.getStepId());
                return factorInOrder;
            }
        }
        log.debug("No more MFA factors to process based on policy. All registered and required factors might be completed or no suitable next step found.");
        return null;
    }

    @Override
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        Assert.notNull(factorType, "FactorType cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        // 실제로는 factorType 또는 ctx의 currentFactorOptions 에서 RetryPolicy 설정을 가져와야 함
        // 여기서는 기본 정책 반환
        int maxAttempts = 3;
      /*  if (ctx.getCurrentFactorOptions() != null && ctx.getCurrentFactorOptions().getRetryPolicy() != null) {
            maxAttempts = ctx.getCurrentFactorOptions().getRetryPolicy().getMaxAttempts();
        }*/
        log.debug("Providing retry policy (max attempts: {}) for factor {} (user {}, session {})",
                maxAttempts, factorType, ctx.getUsername(), ctx.getMfaSessionId());
        return new RetryPolicy(maxAttempts);
    }

    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");

        // FactorContext에 이미 등록된 팩터 정보가 있다면 그것을 우선 사용
        if (ctx != null && !CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return ctx.getRegisteredMfaFactors().contains(factorType);
        }

        // 아니라면 DB에서 사용자 정보 조회
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
            // mfaFactors 필드가 콤마로 구분된 AuthType 문자열이라고 가정 (예: "OTT,PASSKEY")
            return Arrays.stream(user.getMfaFactors().split(","))
                    .map(String::trim)
                    .map(s -> {
                        try {
                            return AuthType.valueOf(s.toUpperCase());
                        } catch (IllegalArgumentException e) {
                            log.warn("Invalid MFA factor string '{}' for user {}", s, user.getUsername());
                            return null;
                        }
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            log.error("Error parsing MFA factors for user {}: {}", user.getUsername(), e.getMessage());
            return Collections.emptySet();
        }
    }

    /**
     * 사용자의 등록된 MFA 요소 목록을 가져옵니다.
     * Users 엔티티의 mfaFactors 필드를 파싱하여 사용합니다.
     *
     * @param username 사용자 이름
     * @return 등록된 AuthType 목록. 없거나 파싱 실패 시 빈 목록 반환.
     */
    public List<AuthType> getRegisteredMfaFactorsForUser(String username) {
        if (!StringUtils.hasText(username)) {
            return Collections.emptyList();
        }
        return new ArrayList<>(userRepository.findByUsername(username)
                .map(this::parseMfaFactors) // Users 객체에서 mfaFactors 필드 파싱
                .orElse(Collections.emptySet()));
    }

    private Set<AuthType> parseMfaFactors(Users user) {
        if (user == null || !StringUtils.hasText(user.getMfaFactors())) {
            return Collections.emptySet();
        }
        try {
            // mfaFactors 필드는 쉼표로 구분된 AuthType 문자열로 가정 (예: "OTT,PASSKEY")
            return Arrays.stream(user.getMfaFactors().split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .map(s -> {
                        try {
                            return AuthType.valueOf(s.toUpperCase());
                        } catch (IllegalArgumentException e) {
                            log.warn("Invalid MFA factor string '{}' for user {}", s, user.getUsername());
                            return null;
                        }
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            log.error("Error parsing MFA factors for user {}: {}", user.getUsername(), e.getMessage());
            return Collections.emptySet();
        }
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
            log.warn("DefaultMfaPolicyProvider: Error retrieving PlatformConfig or MFA flow configuration: {}", e.getMessage());
        }
        return null;
    }


}