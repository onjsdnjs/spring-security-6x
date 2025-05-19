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

@Component
@Slf4j
public final class IdentityDslRegistry<H extends HttpSecurityBuilder<H>> // H는 형식적으로 유지
        extends AbstractFlowRegistrar<H> implements IdentityAuthDsl {

    public IdentityDslRegistry(ApplicationContext applicationContext) {
        super(PlatformConfig.builder(),
                Objects.requireNonNull(applicationContext, "applicationContext cannot be null")
        );
        log.info("IdentityDslRegistry initialized with ApplicationContext.");
    }

    @Override
    public IdentityAuthDsl global(SafeHttpCustomizer<HttpSecurity> customizer) {
        Objects.requireNonNull(customizer, "global customizer cannot be null");
        platformBuilder.global(customizer); // PlatformConfig.Builder에 저장
        log.debug("Global HttpSecurity customizer registered in PlatformConfig.Builder.");
        return this;
    }

    @Override
    public IdentityStateDsl form(Customizer<FormDslConfigurer> customizer) throws Exception {
        log.debug("Registering Form authentication options.");
        return registerAuthenticationMethod(AuthType.FORM, customizer, 100, FormDslConfigurer.class);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer) throws Exception {
        log.debug("Registering Rest authentication options.");
        return registerAuthenticationMethod(AuthType.REST, customizer, 200, RestDslConfigurer.class);
    }

    @Override
    public IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer) throws Exception {
        log.debug("Registering OTT authentication options.");
        return registerAuthenticationMethod(AuthType.OTT, customizer, 300, OttDslConfigurer.class);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer) throws Exception {
        log.debug("Registering Passkey authentication options.");
        return registerAuthenticationMethod(AuthType.PASSKEY, customizer, 400, PasskeyDslConfigurer.class);
    }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) throws Exception {
        log.debug("Registering MFA (Multi-Factor Authentication) flow options.");
        return registerMultiStepFlow(customizer);
    }

    @Override
    public PlatformConfig build() {
        PlatformConfig config = platformBuilder.build();
        log.info("PlatformConfig built with {} authentication flows.", config.getFlows().size());
        return config;
    }
}