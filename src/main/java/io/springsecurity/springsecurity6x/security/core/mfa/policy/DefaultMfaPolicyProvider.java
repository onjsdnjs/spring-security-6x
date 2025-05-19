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

    // 1차 인증 성공 후 FactorContext 초기화 및 첫 MFA 단계 결정
    @Override
    public void evaluateMfaRequirementAndDetermineInitialStep(Authentication primaryAuthentication, FactorContext ctx) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        Assert.isTrue(Objects.equals(primaryAuthentication.getName(), ctx.getUsername()),
                "Username in FactorContext must match primaryAuthentication's name.");
        Assert.isTrue(ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED,
                "evaluateMfaRequirementAndDetermineInitialStep should be called when FactorContext state is PRIMARY_AUTHENTICATION_COMPLETED.");

        String username = ctx.getUsername();
        Optional<Users> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            log.warn("User {} not found. MFA policy evaluation cannot proceed.", username);
            ctx.setMfaRequiredAsPerPolicy(false);
            // 이 경우, 더 이상 진행할 수 없으므로 터미널 상태로 변경하거나, 1차 인증 성공 핸들러가 이 상태를 보고 처리.
            // 여기서는 MFA 불필요로 설정하고, 호출한 핸들러가 최종 토큰을 발행하도록 유도.
            ctx.changeState(MfaState.ALL_FACTORS_COMPLETED); // MFA가 필요 없으므로 바로 완료 상태로 간주
            return;
        }

        Users user = userOptional.get();
        boolean mfaEnabledForUser = user.isMfaEnabled(); // DB에 mfaEnabled 필드가 있다고 가정
        ctx.setMfaRequiredAsPerPolicy(mfaEnabledForUser);

        if (mfaEnabledForUser) {
            Set<AuthType> registeredFactors = parseRegisteredMfaFactorsFromUser(user);
            ctx.setRegisteredMfaFactors(registeredFactors.isEmpty() ? EnumSet.noneOf(AuthType.class) : EnumSet.copyOf(registeredFactors));

            if (CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
                log.warn("MFA is enabled for user '{}', but no MFA factors are registered in DB. MFA cannot proceed.", username);
                ctx.setMfaRequiredAsPerPolicy(false); // 실제 진행 불가
                ctx.changeState(MfaState.ALL_FACTORS_COMPLETED); // 또는 MFA_CONFIGURATION_ERROR 같은 상태 정의
            } else {
                // 첫 번째 처리할 Factor 결정 (등록된 Factor 중 우선순위가 가장 높은 것)
                AuthType initialFactor = determineNextFactorInternal(ctx.getRegisteredMfaFactors(), ctx.getCompletedMfaFactors());
                if (initialFactor != null) {
                    ctx.setCurrentProcessingFactor(initialFactor);
                    ctx.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION); // 다음은 이 Factor에 대한 챌린지 시작
                    log.info("MFA required for user {}. Initial factor set to: {}. New state: {}. Session: {}",
                            username, initialFactor, ctx.getCurrentState(), ctx.getMfaSessionId());
                } else {
                    // 등록된 Factor는 있지만, 정책상 진행할 첫 Factor가 없는 이상한 경우 (예: 모두 이미 완료됨)
                    // 이 경우는 거의 발생하지 않아야 함.
                    log.warn("MFA required for user '{}', registered factors exist, but no initial factor determined (possibly all completed). Current state: {}. Session: {}",
                            username, ctx.getCurrentState(), ctx.getMfaSessionId());
                    // 이 경우, 모든 Factor가 이미 완료된 것으로 간주하거나, Factor 선택 화면으로 보낼 수 있음.
                    // 여기서는 선택 화면으로 유도
                    ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                }
            }
        } else {
            log.info("MFA not enabled for user {}. No MFA required. Session: {}", username, ctx.getMfaSessionId());
            ctx.changeState(MfaState.ALL_FACTORS_COMPLETED); // MFA 불필요 시 바로 완료 상태로
        }
    }

    private Set<AuthType> parseRegisteredMfaFactorsFromUser(Users user) {
        String mfaFactorsString = user.getMfaFactors(); // Users 엔티티에 getMfaFactors()가 있다고 가정
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

    // 다음 처리할 MFA Factor 결정
    @Override
    @Nullable
    public AuthType determineNextFactorToProcess(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");
        if (!ctx.isMfaRequiredAsPerPolicy() || CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return null;
        }
        return determineNextFactorInternal(ctx.getRegisteredMfaFactors(), ctx.getCompletedMfaFactors());
    }

    // 실제 다음 Factor 결정 로직 (플랫폼 정책에 따라 우선순위 정의)
    @Nullable
    private AuthType determineNextFactorInternal(Set<AuthType> registered, Set<AuthType> completed) {
        // 예시 우선순위: PASSKEY > OTT (실제 운영 환경에서는 더 정교한 정책 필요)
        List<AuthType> processingOrder = List.of(AuthType.PASSKEY, AuthType.OTT, AuthType.RECOVERY_CODE); // RECOVERY_CODE 추가

        for (AuthType factorInOrder : processingOrder) {
            if (registered.contains(factorInOrder) && (completed == null || !completed.contains(factorInOrder))) {
                log.debug("Next MFA factor determined: {}", factorInOrder);
                return factorInOrder;
            }
        }
        log.debug("No more MFA factors to process based on policy. All registered and required factors might be completed.");
        return null;
    }

    // Factor별 재시도 정책 반환
    @Override
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        Assert.notNull(factorType, "FactorType cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");
        // 단순 기본 정책 (모든 Factor에 대해 3회)
        log.debug("Providing default retry policy (3 attempts) for factor {} (user {}, session {})",
                factorType, ctx.getUsername(), ctx.getMfaSessionId());
        return new RetryPolicy(3); // 기본 3회. FactorType별, 사용자별 정책 확장 가능
    }

    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");
        // FactorContext에서 이미 로드된 registeredMfaFactors를 우선 사용
        if (ctx != null && !CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors())) {
            return ctx.getRegisteredMfaFactors().contains(factorType);
        }
        // 컨텍스트에 정보가 없다면 DB에서 직접 조회 (1차 인증 성공 전 등)
        return userRepository.findByUsername(username)
                .map(user -> parseRegisteredMfaFactorsFromUser(user).contains(factorType))
                .orElse(false);
    }
}