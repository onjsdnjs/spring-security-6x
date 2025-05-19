package io.springsecurity.springsecurity6x.security.core.dsl.common;


import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Objects;

@Slf4j
public abstract class AbstractOptionsBuilderConfigurer<
        T extends AbstractOptionsBuilderConfigurer<T, B, O, OB, C>,
        B extends HttpSecurityBuilder<B>, // HttpSecurityBuilder 타입
        O extends AuthenticationProcessingOptions,
        OB extends AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder<O, OB>,
        C extends OptionsBuilderDsl<O, C> & SecurityConfigurerDsl>
        extends AbstractHttpConfigurer<T, B> // AbstractHttpConfigurer의 T는 CfgImpl
        implements OptionsBuilderDsl<O, C> { // OptionsBuilderDsl의 S는 CfgInterface

    protected final OB optionsBuilder;
    @Setter
    private ApplicationContext applicationContext;

    protected AbstractOptionsBuilderConfigurer(OB optionsBuilder) {
        this.optionsBuilder = Objects.requireNonNull(optionsBuilder, "optionsBuilder cannot be null");
    }

    protected final ApplicationContext getApplicationContext() {
        if (this.applicationContext == null) {
            B builder = getBuilder();
            if (builder != null) {
                this.applicationContext = builder.getSharedObject(ApplicationContext.class);
            }
            if (this.applicationContext == null) {
                log.warn("ApplicationContext could not be retrieved from HttpSecurityBuilder for {}. ", this.getClass().getSimpleName());
            }
        }
        return this.applicationContext;
    }

    protected OB getOptionsBuilder() {
        return this.optionsBuilder;
    }

    // 하위 클래스에서 self()를 CfgInterface 타입으로 반환하도록 구현해야 함
    // 하지만 DSL 체이닝을 위해 실제로는 CfgImpl 타입을 반환하고 CfgInterface로 업캐스팅
    protected abstract T self(); // 구체 구현체 반환용

    @Override
    public O buildConcreteOptions() {
        return this.optionsBuilder.build();
    }

    // OptionsBuilderDsl 메소드들은 CfgInterface 타입을 반환
    @Override
    public C loginProcessingUrl(String url) {
        getOptionsBuilder().loginProcessingUrl(url);
        return (C) self();
    }

    @Override
    public C successHandler(AuthenticationSuccessHandler handler) {
        getOptionsBuilder().successHandler(handler);
        return (C) self();
    }

    @Override
    public C failureHandler(AuthenticationFailureHandler handler) {
        getOptionsBuilder().failureHandler(handler);
        return (C) self();
    }

    @Override
    public C securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
        return (C) self();
    }

    @Override
    public C disableCsrf() {
        getOptionsBuilder().csrfDisabled(true);
        return (C) self();
    }

    @Override
    public C cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().cors(customizer);
        return (C) self();
    }

    @Override
    public C headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().headers(customizer);
        return (C) self();
    }

    @Override
    public C sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().sessionManagement(customizer);
        return (C) self();
    }

    @Override
    public C logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().logout(customizer);
        return (C) self();
    }

    @Override
    public C rawHttp(SafeHttpCustomizer<HttpSecurity> customizer) {
        getOptionsBuilder().rawHttp(customizer);
        return (C) self();
    }

    @Override
    public abstract void configure(B builder) throws Exception;
}