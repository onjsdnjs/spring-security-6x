package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.auth.mfa.MfaAuthenticationFeature;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

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
        this.feature = feature;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {}

    /**
     * flow의 stepConfigs 에서 이 Feature에 해당하는 Step만 적용
     */
    @Override
    public void configure(FlowContext fc) throws Exception {
        List<AuthenticationStepConfig> steps = fc.flow().stepConfigs();

        if (feature instanceof MfaAuthenticationFeature) {
            feature.apply(fc.http(), steps, fc.flow().stateConfig());
        }

        if (steps.isEmpty()) return;
        for (AuthenticationStepConfig step : steps) {
            if (feature.getId().equalsIgnoreCase(step.type())) {
                feature.apply(fc.http(), steps, fc.flow().stateConfig());
            }
        }
    }

    @Override
    public int getOrder() {
        return 300;
    }
}
