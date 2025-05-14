package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractStepAwareDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

public class FormDslConfigurerImpl
        extends AbstractStepAwareDslConfigurer<
        FormOptions,
        FormOptions.Builder,
        FormDslOptionsBuilderConfigurer, // OBI: Options Builder Configurer의 구체적 타입
        FormStepDslConfigurer          // S: 이 클래스가 구현하는 Step-aware DSL 인터페이스
        >
        implements FormStepDslConfigurer {

    public FormDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        // FormDslOptionsBuilderConfigurer 인스턴스를 생성하여 부모 생성자에 전달
        super(stepConfig, new FormDslOptionsBuilderConfigurer());
    }

    @Override
    protected String getAuthTypeName() {
        return AuthType.FORM.name().toLowerCase();
    }

    @Override
    protected FormStepDslConfigurer self() {
        return this;
    }

    @Override
    public FormStepDslConfigurer loginPage(String loginPageUrl) {
        this.optionsConfigurerImpl.loginPage(loginPageUrl); return self();
    }
    @Override
    public FormStepDslConfigurer loginProcessingUrl(String loginProcessingUrl) {
        this.optionsConfigurerImpl.loginProcessingUrl(loginProcessingUrl); return self();
    }
    @Override
    public FormStepDslConfigurer usernameParameter(String usernameParameter) {
        this.optionsConfigurerImpl.usernameParameter(usernameParameter); return self();
    }
    @Override
    public FormStepDslConfigurer passwordParameter(String passwordParameter) {
        this.optionsConfigurerImpl.passwordParameter(passwordParameter); return self();
    }
    @Override
    public FormStepDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        this.optionsConfigurerImpl.defaultSuccessUrl(defaultSuccessUrl, alwaysUse); return self();
    }
    @Override
    public FormStepDslConfigurer failureUrl(String failureUrl) {
        this.optionsConfigurerImpl.failureUrl(failureUrl); return self();
    }
    @Override
    public FormStepDslConfigurer permitAll() {
        this.optionsConfigurerImpl.permitAll(); return self();
    }
    @Override
    public FormStepDslConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        this.optionsConfigurerImpl.successHandler(successHandler); return self();
    }
    @Override
    public FormStepDslConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        this.optionsConfigurerImpl.failureHandler(failureHandler); return self();
    }
    @Override
    public FormStepDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        this.optionsConfigurerImpl.securityContextRepository(repository); return self();
    }
    @Override
    public FormStepDslConfigurer rawLogin(SafeHttpFormLoginCustomizer customizer) {
        this.optionsConfigurerImpl.rawLogin(customizer); return self();
    }

    @Override
    public FormStepDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        this.optionsConfigurerImpl.rawHttp(customizer); return self();
    }
    @Override
    public FormStepDslConfigurer disableCsrf() {
        this.optionsConfigurerImpl.disableCsrf(); return self();
    }
    @Override
    public FormStepDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.cors(customizer); return self();
    }
    @Override
    public FormStepDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.headers(customizer); return self();
    }
    @Override
    public FormStepDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.sessionManagement(customizer); return self();
    }
    @Override
    public FormStepDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.logout(customizer); return self();
    }

    // buildConcreteOptions는 FormDslConfigurer (OptionsBuilderDsl)에 의해 요구되지만,
    // 이 클래스는 Step-aware 이므로 직접 호출될 일이 없고, toConfig() 내부에서 optionsConfigurerImpl.buildConcreteOptions()가 호출됨.
    // FormStepDslConfigurer 인터페이스가 OptionsBuilderDsl을 확장하지 않도록 수정해야 함.
    // 또는 FormStepDslConfigurer에 해당 메소드가 없어야 함.
    // 여기서는 FormDslConfigurer가 OptionsBuilderDsl을 확장한다고 가정하고,
    // FormStepDslConfigurer는 FormDslConfigurer를 확장하므로 해당 메소드 시그니처가 존재함.
    // 그러나 실제 사용은 optionsConfigurerImpl을 통함.
    @Override
    public FormOptions buildConcreteOptions() {
        // 이 클래스 레벨에서는 직접 Options를 빌드하지 않고, optionsConfigurerImpl에 위임합니다.
        // 이 메소드는 FormDslConfigurer 인터페이스 (OptionsBuilderDsl 확장) 때문에 필요합니다.
        return this.optionsConfigurerImpl.buildConcreteOptions();
    }


    // --- Method from StepDslConfigurer (via FormStepDslConfigurer) ---
    // AbstractStepAwareDslConfigurer 에서 order(int)를 public으로 제공하고 self()를 반환.
    @Override
    public FormStepDslConfigurer order(int orderValue) {
        super.order(orderValue); // 부모의 order(int) 호출
        return self();
    }
    // getOrder() 와 toConfig()는 AbstractStepAwareDslConfigurer에서 구현됨.
}