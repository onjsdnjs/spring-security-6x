package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.AbstractDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.function.ThrowingConsumer;

import java.util.List;

@Slf4j
public class PasskeyDslConfigurerImpl extends AbstractDslConfigurer<PasskeyOptions.Builder, PasskeyDslConfigurer> implements PasskeyDslConfigurer {

    private int order = 0;

    public PasskeyDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        super(stepConfig, PasskeyOptions.builder());
    }

    @Override
    public PasskeyDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public int order() {
        return this.order;
    }

    @Override
    public PasskeyDslConfigurer rpName(String name) {
        options.rpName(name);
        return this;
    }

    @Override
    public PasskeyDslConfigurer rpId(String id) {
        options.rpId(id);
        return this;
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(String... origins) {
        options.allowedOrigins(List.of(origins));
        return this;
    }

    /**
     * 원시 HttpSecurity 커스터마이저를 안전하게 적용
     */
    public PasskeyDslConfigurer originRaw(Customizer<HttpSecurity> customizer) {
        options.rawHttp(customizer);
        return this;
    }

    @Override
    public PasskeyDslConfigurer targetUrl(String targetUrl) {
        options.targetUrl(targetUrl);
        return this;
    }

    @Override
    public PasskeyDslConfigurer raw(SafeHttpCustomizer safe) {
        return originRaw(wrapSafe(safe));
    }

    private Customizer<HttpSecurity> wrapSafe(SafeHttpCustomizer safe) {
        return http -> {
            try {
                safe.customize(http);
            } catch (Exception e) {
                log.error("Error during raw FormLoginConfigurer customization: {}", e.getMessage());
                log.error(e.getMessage(), e);
                throw new DslConfigurationException(e.getMessage(), e);
            }
        };
    }

    /**
     * DSL 설정을 HttpSecurity에 적용하는 Consumer 반환
     */
    @Override
    public ThrowingConsumer<HttpSecurity> toFlowCustomizer() {
        return http -> {
            PasskeyOptions optsBuilt = options.build();
            try {
                optsBuilt.applyCommon(http);
            } catch (Exception e) {
                // 예외는 내부에서 로깅 또는 무시
            }
        };
    }

    /**
     * AuthenticationStepConfig 생성 및 옵션 저장
     */
    @Override
    public AuthenticationStepConfig toConfig() {
        PasskeyOptions optsBuilt = options.build();
        AuthenticationStepConfig step = stepConfig();
        step.type("passkey");
        step.options().put("_options", optsBuilt);
        return step;
    }
}
