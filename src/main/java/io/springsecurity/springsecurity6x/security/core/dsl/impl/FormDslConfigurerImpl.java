package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.function.ThrowingConsumer;


/**
 * Form 로그인 DSL 구현체
 */
public class FormDslConfigurerImpl extends AbstractDslConfigurer<FormOptions.Builder, FormDslConfigurer> implements FormDslConfigurer {

    public FormDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        super(stepConfig, FormOptions.builder());
    }

    @Override
    public FormDslConfigurer loginPage(String loginPageUrl) {
        options.loginPage(loginPageUrl);
        return this;
    }

    @Override
    public FormDslConfigurer loginProcessingUrl(String loginProcessingUrl) {
        options.loginProcessingUrl(loginProcessingUrl);
        return this;
    }

    @Override
    public FormDslConfigurer usernameParameter(String usernameParameter) {
        options.usernameParameter(usernameParameter);
        return this;
    }

    @Override
    public FormDslConfigurer passwordParameter(String passwordParameter) {
        options.passwordParameter(passwordParameter);
        return this;
    }

    @Override
    public FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        options.defaultSuccessUrl(defaultSuccessUrl, alwaysUse);
        return this;
    }

    @Override
    public FormDslConfigurer failureUrl(String failureUrl) {
        options.failureUrl(failureUrl);
        return this;
    }

    @Override
    public FormDslConfigurer permitAll() {
        options.isPermitAll();
        return this;
    }

    @Override
    public FormDslConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        options.successHandler(successHandler);
        return this;
    }

    @Override
    public FormDslConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        options.failureHandler(failureHandler);
        return this;
    }

    @Override
    public FormDslConfigurer securityContextRepository(SecurityContextRepository repo) {
        options.securityContextRepository(repo);
        return this;
    }


    public FormDslConfigurer originRaw(Customizer<HttpSecurity> customizer) {
        options.rawHttp(customizer);
        return this;
    }
    @Override
    public FormDslConfigurer raw(SafeHttpCustomizer customizer) {
        return originRaw(wrapSafe(customizer));
    }

    private Customizer<HttpSecurity> wrapSafe(SafeHttpCustomizer safe) {
        return http -> {
            try {
                safe.customize(http);
            } catch (Exception e) {
                // 내부 로그 또는 무시
                System.err.println("Global customizer exception: " + e.getMessage());
            }
        };
    }

    /**
     * FormLoginConfigurer 레벨에서 raw 커스터마이징을 수행합니다.
     */
    public FormDslConfigurer originRawLogin(Customizer<FormLoginConfigurer<HttpSecurity>> loginCustomizer) {
        options.rawFormLogin(loginCustomizer);
        return this;
    }

    @Override
    public FormDslConfigurer rawLogin(SafeHttpFormLoginCustomizer customizer) {
        return originRawLogin(wrapFormLOginSafe(customizer));
    }

    private Customizer<FormLoginConfigurer<HttpSecurity>> wrapFormLOginSafe(SafeHttpFormLoginCustomizer safe) {
        return http -> {
            try {
                safe.customize(http);
            } catch (Exception e) {
                // 내부 로그 또는 무시
                System.err.println("Global customizer exception: " + e.getMessage());
            }
        };
    }

    /**
     * DSL 설정을 HttpSecurity에 적용하는 Consumer를 반환
     */
    @Override
    public ThrowingConsumer<HttpSecurity> toFlowCustomizer() {
        return http -> {
            FormOptions optsBuilt = options.build();
            try {
                optsBuilt.applyCommon(http);
            } catch (Exception e) {
                // 예외는 내부에서 처리, 로그를 남기거나 무시
            }
            http.formLogin(form -> {
                Customizer<FormLoginConfigurer<HttpSecurity>> rawLogin = optsBuilt.getRawFormLogin();
                if (rawLogin != null) {
                    try {
                        rawLogin.customize(form);
                    } catch (Exception ex) {
                        // 내부 예외는 무시 또는 로깅
                    }
                }
            });
        };
    }

    /**
     * AuthenticationStepConfig 생성 및 옵션 저장
     */
    public AuthenticationStepConfig toConfig() {
        FormOptions optsBuilt = options.build();
        AuthenticationStepConfig step = getStepConfig();
        step.type("form");
        step.options().put("_options", optsBuilt);
        return step;
    }
}