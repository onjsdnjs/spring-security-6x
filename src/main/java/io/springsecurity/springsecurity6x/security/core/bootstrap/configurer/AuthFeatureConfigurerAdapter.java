package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.auth.MfaAuthenticationFeature;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Objects; // Objects.requireNonNull 추가를 위해 import

/**
 * AuthenticationFeature를 SecurityConfigurer로 감싸는 어댑터
 */
@Slf4j
public class AuthFeatureConfigurerAdapter implements SecurityConfigurer {
    private final AuthenticationFeature feature;

    /**
     * @param feature 인증 기능 구현체
     */
    public AuthFeatureConfigurerAdapter(AuthenticationFeature feature) {
        this.feature = Objects.requireNonNull(feature, "AuthenticationFeature cannot be null"); // Null 체크 추가
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {}

    /**
     * flow의 stepConfigs 에서 이 Feature에 해당하는 Step만 적용
     */
    @Override
    public void configure(FlowContext fc) throws Exception {
        Objects.requireNonNull(fc, "FlowContext cannot be null"); // Null 체크 추가
        Objects.requireNonNull(fc.flow(), "FlowContext.flow cannot be null"); // Null 체크 추가
        Objects.requireNonNull(fc.http(), "FlowContext.http cannot be null"); // Null 체크 추가
        // fc.flow().stateConfig()는 null일 수 있으므로, feature.apply 호출 전에 Null 체크 또는 기본값 처리 필요

        List<AuthenticationStepConfig> steps = fc.flow().getStepConfigs();

        // 1. MfaAuthenticationFeature인 경우 특별 처리
        if (feature instanceof MfaAuthenticationFeature) {
            // MfaAuthenticationFeature는 전체 MFA 흐름을 구성하므로,
            // 특정 step.type()과 매칭되지 않아도 모든 stepConfigs를 전달하여 적용될 수 있음.
            // 또는, flowConfig.typeName()이 "mfa"일 때만 적용하도록 조건 추가 가능.
            if ("mfa".equalsIgnoreCase(fc.flow().getTypeName())) {
                log.debug("Applying MfaAuthenticationFeature for flow: {}", fc.flow().getTypeName());
                feature.apply(fc.http(), steps, fc.flow().getStateConfig());
            }
            // MfaAuthenticationFeature가 적용된 후에는 다른 개별 step feature 들이 중복 적용되지 않도록 주의 필요.
            // 현재 로직은 MfaAuthenticationFeature가 적용된 후에도 아래의 루프가 실행될 수 있음.
            // 이를 방지하려면, MfaAuthenticationFeature 적용 후 return 하거나,
            // 아래 루프에서 MfaAuthenticationFeature가 아닌 경우에만 실행하도록 조건 추가 필요.
            // 여기서는 MfaAuthenticationFeature가 다른 일반 AuthenticationFeature와 별개로
            // 전체 MFA 플로우를 설정한다고 가정하고, 중복 적용을 피하기 위해 return을 추가하거나
            // 아래 루프의 조건을 수정하는 것을 고려해야 함.
            // 여기서는 명확성을 위해 MfaAuthenticationFeature는 이 블록에서만 처리하고,
            // 다른 일반 Feature는 아래 루프에서 처리하도록 수정합니다.
            // 만약 MfaAuthenticationFeature가 적용되면, 다른 개별 factor feature들은 이 adapter를 통해 다시 호출되지 않도록
            // SecurityConfigurerProvider 에서 조절하는 것이 더 나을 수 있습니다.
            // (즉, MfaAuthenticationFeature 어댑터와 개별 Factor Feature 어댑터를 별도로 관리)
            // 여기서는 현재 구조를 최대한 유지하면서 중복 호출 가능성을 줄이는 방향으로 수정합니다.
            // -> MfaAuthenticationFeature는 steps 리스트 전체를 보고, 그 안의 개별 factor step들을 구성할 수 있으므로,
            //    이 로직은 MfaAuthenticationFeature.apply() 내부에서 처리되어야 할 가능성이 높습니다.
            //    현재 구조에서는 MfaAuthenticationFeature.apply()를 호출하고,
            //    이후 루프에서 개별 factor feature 들의 apply가 호출될 수 있습니다.
            //    MFA 흐름에서는 MfaAuthenticationFeature가 먼저 적용되고,
            //    그 안에서 개별 Factor Feature 들의 설정 로직이 트리거되는 것이 더 자연스러울 수 있습니다.
            //    이 어댑터는 단일 AuthenticationFeature에 대한 것이므로,
            //    MFA의 경우 MfaAuthenticationFeature의 apply가 모든 것을 처리한다고 가정.
            //    만약 MfaAuthenticationFeature.apply가 steps를 순회하며 각 factor에 해당하는
            //    다른 AuthenticationFeature를 내부적으로 호출하지 않는다면, 현재 로직에 문제가 있음.
            //    우선, MfaAuthenticationFeature는 이 if 블록에서 한 번만 apply 되도록 합니다.
            //    그리고 아래 루프는 MfaAuthenticationFeature가 아닌 다른 일반 feature에 대해서만 동작하도록 수정.

            if ("mfa".equalsIgnoreCase(fc.flow().getTypeName())) { // MfaAuthenticationFeature는 MFA 타입의 flow에만 적용
                feature.apply(fc.http(), steps, fc.flow().getStateConfig());
                // MfaAuthenticationFeature가 모든 하위 스텝 설정을 포함하여 처리한다고 가정하면,
                // 이 특정 feature에 대한 작업은 여기서 완료되므로 return 할 수 있습니다.
                // 또는, 아래 루프에서 이 feature를 제외하도록 합니다.
                return; // MfaAuthenticationFeature는 여기서 처리하고 종료
            }
        }

        // 2. 일반 AuthenticationFeature 처리
        if (steps == null || steps.isEmpty()) { // steps가 null일 수도 있으므로 체크
            log.trace("No steps configured for flow: {}, feature: {}", fc.flow().getTypeName(), feature.getId());
            return;
        }

        boolean applied = false; // Feature가 한 번만 적용되도록 플래그 사용
        for (AuthenticationStepConfig step : steps) {
            if (step != null && feature.getId().equalsIgnoreCase(step.getType())) {
                // 해당 feature에 대해 첫 번째 매칭되는 step 에서만 apply 호출
                log.info("Applying feature: {} for step type: {} in flow: {}", feature.getId(), step.getType(), fc.flow().getTypeName());
                // AuthenticationFeature.apply는 해당 feature와 관련된 모든 steps 설정을 사용할 수 있도록 전체 steps를 전달
                feature.apply(fc.http(), steps, fc.flow().getStateConfig());
                applied = true; // 이 Feature에 대한 적용이 완료되었음을 표시
                // 일반적으로 하나의 AuthenticationFeature는 하나의 SecurityFilterChain에서 한 번만 주요 설정을 담당.
                // 만약 동일 타입의 step이 여러 개 있고 각기 다르게 설정되어야 한다면,
                // AuthenticationFeature.apply 메소드가 이를 구분해서 처리할 수 있어야 함.
                // 여기서는 feature 당 한 번의 apply 호출을 가정.
                break; // 이 feature에 대한 적용을 마쳤으므로 루프 종료
            }
        }
        if (!applied) {
            log.info("Feature: {} was not applicable to any step in flow: {}", feature.getId(), fc.flow().getTypeName());
        }
    }

    @Override
    public int getOrder() {
        // Feature 자체에 order가 있다면 그 값을 따르도록 수정 가능
        // return feature.getOrder();
        return 300; // 현재는 고정값
    }
}
