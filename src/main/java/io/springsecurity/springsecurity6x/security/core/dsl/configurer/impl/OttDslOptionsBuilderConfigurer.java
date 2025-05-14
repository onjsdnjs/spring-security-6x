package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

// S 타입을 OttStepDslConfigurer로 명확히 함
public class OttDslOptionsBuilderConfigurer
        extends AbstractOptionsBuilderConfigurer<OttOptions, OttOptions.Builder, OttStepDslConfigurer>
        implements OttStepDslConfigurer { // 구현하는 인터페이스도 OttStepDslConfigurer

    private final ApplicationContext applicationContext;

    public OttDslOptionsBuilderConfigurer(ApplicationContext applicationContext) {
        super(OttOptions.builder());
        Assert.notNull(applicationContext, "ApplicationContext cannot be null");
        this.applicationContext = applicationContext;
    }

    @Override
    protected OttStepDslConfigurer self() {
        return this;
    }

    // OttStepDslConfigurer 인터페이스의 모든 메소드 구현
    @Override
    public OttStepDslConfigurer loginProcessingUrl(String url) {
        this.optionsBuilder.loginProcessingUrl(url); return self();
    }

    @Override
    public OttStepDslConfigurer targetUrl(String url) {
        this.optionsBuilder.targetUrl(url); return self();
    }

    @Override
    public OttStepDslConfigurer defaultSubmitPageUrl(String url) {
        this.optionsBuilder.defaultSubmitPageUrl(url); return self();
    }

    @Override
    public OttStepDslConfigurer tokenGeneratingUrl(String url) {
        this.optionsBuilder.tokenGeneratingUrl(url); return self();
    }

    @Override
    public OttStepDslConfigurer showDefaultSubmitPage(boolean show) {
        this.optionsBuilder.showDefaultSubmitPage(show); return self();
    }

    @Override
    public OttStepDslConfigurer tokenService(OneTimeTokenService service) {
        this.optionsBuilder.tokenService(service); return self();
    }

    @Override
    public OttStepDslConfigurer tokenServiceBeanName(String beanName) {
        Assert.hasText(beanName, "beanName cannot be empty");
        try {
            OneTimeTokenService service = applicationContext.getBean(beanName, OneTimeTokenService.class);
            this.optionsBuilder.tokenService(service);
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalArgumentException("No OneTimeTokenService bean found with name: " + beanName, e);
        }
        return self();
    }

    @Override
    public OttStepDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        this.optionsBuilder.tokenGenerationSuccessHandler(handler); return self();
    }

    @Override
    public OttStepDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        super.rawHttp(customizer); return self();
    }
    @Override
    public OttStepDslConfigurer disableCsrf() {
        super.disableCsrf(); return self();
    }
    @Override
    public OttStepDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        super.cors(customizer); return self();
    }
    @Override
    public OttStepDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        super.headers(customizer); return self();
    }
    @Override
    public OttStepDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        super.sessionManagement(customizer); return self();
    }
    @Override
    public OttStepDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        super.logout(customizer); return self();
    }

    // buildConcreteOptions는 OptionsBuilderDsl 인터페이스의 일부로, 부모 클래스에 구현되어 있음
    // @Override
    // public OttOptions buildConcreteOptions() {
    // return super.buildConcreteOptions();
    // }

    // OttStepDslConfigurer 인터페이스에는 order()가 정의되어 있지만,
    // 이 클래스는 OptionsBuilder이므로 order를 직접 다루지 않음.
    // order()는 AbstractStepAwareDslConfigurer를 상속하는 클래스에서 구현.
    @Override
    public OttStepDslConfigurer order(int order) {
        // 이 클래스에서 order를 직접 설정하지 않음. AbstractStepAwareDslConfigurer에서 처리.
        // 호출되지 않도록 하거나, 호출 시 예외 발생 또는 무시.
        // 여기서는 인터페이스 만족을 위해 추가하되, 실제 로직은 StepAware Configurer에 있음.
        return self();
    }

    @Override
    public AuthenticationStepConfig toConfig() {
        return null;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
