package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * 플랫폼의 최상위 DSL 진입점 및 다양한 인증 흐름 등록을 담당합니다.
 * 이 클래스는 특정 HttpSecurity 인스턴스에 대한 설정을 구성합니다.
 * @param <H> 이 DSL Registry가 적용될 HttpSecurityBuilder의 타입
 */
@Component
@Slf4j
public final class IdentityDslRegistry<H extends HttpSecurityBuilder<H>> // 제네릭 H 추가
        extends AbstractFlowRegistrar<H> implements IdentityAuthDsl {

    /**
     * 생성자.
     * @param applicationContext Spring ApplicationContext
     * @param httpSecurityBuilder 이 DSL Registry가 설정을 적용할 HttpSecurityBuilder 인스턴스
     */
    public IdentityDslRegistry(ApplicationContext applicationContext, H httpSecurityBuilder) {
        super(PlatformConfig.builder(),
                Objects.requireNonNull(applicationContext, "applicationContext cannot be null"),
                Objects.requireNonNull(httpSecurityBuilder, "httpSecurityBuilder cannot be null"));
        log.info("IdentityDslRegistry initialized for HttpSecurityBuilder: {}", httpSecurityBuilder.hashCode());
    }

    @Override
    public IdentityAuthDsl global(SafeHttpCustomizer<HttpSecurity> customizer) {
        Objects.requireNonNull(customizer, "global customizer cannot be null");
        platformBuilder.global(customizer);
        log.debug("Global HttpSecurity customizer registered.");
        return this;
    }

    @Override
    public IdentityStateDsl form(Customizer<FormDslConfigurer> customizer) throws Exception {
        log.debug("Registering Form authentication flow.");
        return registerAuthenticationMethod(AuthType.FORM, customizer, 100, FormDslConfigurer.class);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer) throws Exception {
        log.debug("Registering Rest authentication flow.");
        return registerAuthenticationMethod(AuthType.REST, customizer, 200, RestDslConfigurer.class);
    }

    @Override
    public IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer) throws Exception {
        log.debug("Registering OTT authentication flow.");
        return registerAuthenticationMethod(AuthType.OTT, customizer, 300, OttDslConfigurer.class);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer) throws Exception {
        log.debug("Registering Passkey authentication flow.");
        return registerAuthenticationMethod(AuthType.PASSKEY, customizer, 400, PasskeyDslConfigurer.class);
    }

    // public IdentityStateDsl recoveryCode(Customizer<RecoveryCodeDslConfigurer> customizer) throws Exception {
    //     log.debug("Registering Recovery Code authentication flow.");
    //     return registerAuthenticationMethod(AuthType.RECOVERY_CODE, customizer, 450, RecoveryCodeDslConfigurer.class);
    // }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) throws Exception {
        log.debug("Registering MFA (Multi-Factor Authentication) flow.");
        return registerMultiStepFlow(customizer);
    }

    @Override
    public PlatformConfig build() {
        PlatformConfig config = platformBuilder.build();
        log.info("PlatformConfig built with {} authentication flows.", config.getFlows().size());
        return config;
    }
}