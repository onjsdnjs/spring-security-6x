package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer; // 추가
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer; // FormDslConfigurer 인터페이스 경로
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import org.springframework.security.config.Customizer; // 추가
import org.springframework.security.config.annotation.web.builders.HttpSecurity; // 추가
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer; // 추가
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer; // 추가
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer; // 추가
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer; // 추가
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

public class FormDslOptionsBuilderConfigurer
        extends AbstractOptionsBuilderConfigurer<FormOptions, FormOptions.Builder, FormDslConfigurer>
        implements FormDslConfigurer {

    public FormDslOptionsBuilderConfigurer() {
        super(FormOptions.builder());
    }

    @Override
    protected FormDslConfigurer self() {
        return this;
    }

    // --- FormDslConfigurer 고유 메소드 구현 ---
    @Override
    public FormDslConfigurer loginPage(String loginPageUrl) {
        this.optionsBuilder.loginPage(loginPageUrl);
        return self();
    }

    @Override
    public FormDslConfigurer loginProcessingUrl(String loginProcessingUrl) {
        this.optionsBuilder.processingUrl(loginProcessingUrl);
        return self();
    }

    @Override
    public FormDslConfigurer usernameParameter(String usernameParameter) {
        this.optionsBuilder.usernameParameter(usernameParameter);
        return self();
    }

    @Override
    public FormDslConfigurer passwordParameter(String passwordParameter) {
        this.optionsBuilder.passwordParameter(passwordParameter);
        return self();
    }

    @Override
    public FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        this.optionsBuilder.defaultSuccessUrl(defaultSuccessUrl, alwaysUse);
        return self();
    }

    @Override
    public FormDslConfigurer failureUrl(String failureUrl) {
        this.optionsBuilder.failureUrl(failureUrl);
        return self();
    }

    @Override
    public FormDslConfigurer permitAll() {
        this.optionsBuilder.permitAll();
        return self();
    }

    @Override
    public FormDslConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        this.optionsBuilder.successHandler(successHandler);
        return self();
    }

    @Override
    public FormDslConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        this.optionsBuilder.failureHandler(failureHandler);
        return self();
    }

    @Override
    public FormDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        this.optionsBuilder.securityContextRepository(repository);
        return self();
    }

    @Override
    public FormDslConfigurer rawLogin(SafeHttpFormLoginCustomizer customizer) {
        // wrapSafeFormLoginCustomizer는 AbstractOptionsBuilderConfigurer에 protected로 있음
        this.optionsBuilder.rawFormLogin(super.wrapSafeFormLoginCustomizer(customizer));
        return self();
    }

    // --- OptionsBuilderDsl 인터페이스의 공통 메소드들 ---
    // AbstractOptionsBuilderConfigurer 에서 이미 구현되어 optionsBuilder에 위임하고 self()를 반환하므로,
    // 여기서는 명시적으로 오버라이드하여 self()의 반환 타입을 FormDslConfigurer로 정확히 맞춥니다.
    @Override
    public FormDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        super.rawHttp(customizer); // 부모의 구현 호출 (optionsBuilder에 설정)
        return self();
    }

    @Override
    public FormDslConfigurer disableCsrf() {
        super.disableCsrf(); // 부모의 구현 호출
        return self();
    }

    @Override
    public FormDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        super.cors(customizer); // 부모의 구현 호출
        return self();
    }

    @Override
    public FormDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        super.headers(customizer); // 부모의 구현 호출
        return self();
    }

    @Override
    public FormDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        super.sessionManagement(customizer); // 부모의 구현 호출
        return self();
    }

    @Override
    public FormDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        super.logout(customizer); // 부모의 구현 호출
        return self();
    }

    // buildConcreteOptions()는 AbstractOptionsBuilderConfigurer에서 상속받아 사용 가능.
    // @Override
    // public FormOptions buildConcreteOptions() {
    // return super.buildConcreteOptions();
    // }
}
