package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.AbstractDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class FormDslConfigurerImpl extends AbstractDslConfigurer<FormOptions.Builder, FormDslConfigurer> implements FormDslConfigurer {

    public FormDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        super(stepConfig, FormOptions.builder());
    }

    @Override
    public FormDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public int order() {
        return order;
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
    public FormDslConfigurer targetUrl(String targetUrl) {
        options.targetUrl(targetUrl);
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
        return originRawLogin(wrapSafeFormLoginCustomizer(customizer));
    }

    private Customizer<FormLoginConfigurer<HttpSecurity>> wrapSafeFormLoginCustomizer(SafeHttpFormLoginCustomizer safeCustomizer) {
        return formLogin -> {
            try {
                safeCustomizer.customize(formLogin);
            } catch (Exception e) {
                log.error("Error during raw FormLoginConfigurer customization: {}", e.getMessage());
                log.error(e.getMessage(), e);
                throw new DslConfigurationException(e.getMessage(), e);
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
            // applyCommon은 AbstractOptions 에 있으며, 내부적으로 HttpSecurity 예외를 던질 수 있음.
            // 필요시 AbstractOptions의 applyCommon 내의 개별 customizer.customize 호출도 try-catch로 감싸 DslConfigurationException 으로 래핑 가능.
            try {
                optsBuilt.applyCommon(http); // 이 안에서 예외가 발생하면 DslConfigurationException 으로 변환되어야 함
            } catch (Exception e) {
                if (e instanceof DslConfigurationException) throw e;
                String errorMessage = String.format("Error applying common options in FormDsl: %s", e.getMessage());
                log.error(errorMessage, e);
                throw new DslConfigurationException(errorMessage, e);
            }

            http.formLogin(form -> {
                Customizer<FormLoginConfigurer<HttpSecurity>> rawLogin = optsBuilt.getRawFormLogin();
                if (rawLogin != null) {
                    // rawLogin.customize(form) 호출은 이미 wrapSafeFormLoginCustomizer를 통해 예외처리 됨
                    rawLogin.customize(form);
                }
            });
        };
    }

    /**
     * AuthenticationStepConfig 생성 및 옵션 저장
     */
    public AuthenticationStepConfig toConfig() {
        FormOptions optsBuilt = options.build();
        AuthenticationStepConfig step = stepConfig();
        step.type("form");
        step.options().put("_options", optsBuilt);
        return step;
    }
}