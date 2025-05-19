package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.Assert;

import java.util.Objects;

@Slf4j
public final class PrimaryAuthDslConfigurerImpl<H extends HttpSecurityBuilder<H>> // 제네릭 H 추가
        implements PrimaryAuthDslConfigurer {

    private Customizer<FormDslConfigurer> formLoginCustomizer;
    private Customizer<RestDslConfigurer> restLoginCustomizer;
    private final ApplicationContext applicationContext; // AuthMethodConfigurerFactory 또는 Configurer 직접 생성 시 사용
    private final H httpSecurityBuilder; // 상위 HttpSecurityBuilder 참조

    /**
     * 생성자.
     * @param applicationContext 하위 DSL Configurer 생성 시 ApplicationContext를 전달하기 위함.
     * @param httpSecurityBuilder 하위 DSL Configurer가 HttpSecurityBuilder에 접근해야 할 경우 전달.
     */
    public PrimaryAuthDslConfigurerImpl(ApplicationContext applicationContext, H httpSecurityBuilder) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
        this.httpSecurityBuilder = Objects.requireNonNull(httpSecurityBuilder, "HttpSecurityBuilder cannot be null");
    }

    @Override
    public PrimaryAuthDslConfigurer formLogin(Customizer<FormDslConfigurer> formLoginCustomizer) {
        Assert.notNull(formLoginCustomizer, "formLoginCustomizer cannot be null");
        this.formLoginCustomizer = formLoginCustomizer;
        this.restLoginCustomizer = null; // 상호 배타적 선택
        return this;
    }

    @Override
    public PrimaryAuthDslConfigurer restLogin(Customizer<RestDslConfigurer> restLoginCustomizer) {
        Assert.notNull(restLoginCustomizer, "restLoginCustomizer cannot be null");
        this.restLoginCustomizer = restLoginCustomizer;
        this.formLoginCustomizer = null; // 상호 배타적 선택
        return this;
    }

    @Override
    public PrimaryAuthenticationOptions buildOptions() {
        PrimaryAuthenticationOptions.Builder optionsBuilder = PrimaryAuthenticationOptions.builder();
        String determinedLoginProcessingUrl = null;

        // AuthMethodConfigurerFactory를 사용하거나 직접 생성하여 HttpSecurityBuilder를 전달
        // (AuthMethodConfigurerFactory가 HttpSecurityBuilder를 받는 형태로 수정되었다고 가정)
        AuthMethodConfigurerFactory factory = new AuthMethodConfigurerFactory(this.applicationContext);

        if (formLoginCustomizer != null) {
            // FormDslConfigurerImpl은 AbstractHttpConfigurer를 상속하므로, builder에 apply되어야 함.
            // 하지만 PrimaryAuthDslConfigurerImpl은 옵션만 빌드하므로, FormDslConfigurerImpl을
            // 임시로 생성하여 옵션만 빌드하고, 실제 HttpSecurity 구성은 MfaDslConfigurerImpl에서 이루어짐.
            // 이 방식은 FormDslConfigurerImpl의 configure() 메소드가 호출되지 않는 문제가 있을 수 있음.
            // 더 나은 방법은 FormDslConfigurer를 통해 FormOptions만 빌드하는 것.
            // 여기서는 FormDslConfigurerImpl을 직접 생성하고 옵션을 가져오는 것으로 가정.

            // FormDslConfigurerImpl<H> formDslBuilder = factory.createConfigurer(AuthType.FORM, this.httpSecurityBuilder, FormDslConfigurerImpl.class);
            // 위 코드는 AuthMethodConfigurerFactory의 시그니처 변경 필요.
            // 제공된 PrimaryAuthDslConfigurerImpl 구조를 최대한 유지하며 수정:
            FormDslConfigurerImpl<H> formDslBuilder = new FormDslConfigurerImpl<>();
            formDslBuilder.setBuilder(this.httpSecurityBuilder); // AbstractHttpConfigurer의 setBuilder 호출
            formDslBuilder.setApplicationContext(this.applicationContext); // ApplicationContext 설정
            formLoginCustomizer.customize(formDslBuilder); // Customizer 적용
            FormOptions builtFormOptions = formDslBuilder.buildConcreteOptions();

            optionsBuilder.formOptions(builtFormOptions);
            determinedLoginProcessingUrl = builtFormOptions.getLoginProcessingUrl();
            log.debug("PrimaryAuth: FormLogin options built. Processing URL: {}", determinedLoginProcessingUrl);

        } else if (restLoginCustomizer != null) {
            RestDslConfigurerImpl<H> restDslBuilder = new RestDslConfigurerImpl<>();
            restDslBuilder.setBuilder(this.httpSecurityBuilder);
            restDslBuilder.setApplicationContext(this.applicationContext);
            restLoginCustomizer.customize(restDslBuilder);
            RestOptions builtRestOptions = restDslBuilder.buildConcreteOptions();

            optionsBuilder.restOptions(builtRestOptions);
            determinedLoginProcessingUrl = builtRestOptions.getLoginProcessingUrl();
            log.debug("PrimaryAuth: RestLogin options built. Processing URL: {}", determinedLoginProcessingUrl);
        } else {
            throw new DslConfigurationException("Either formLogin or restLogin must be configured for primary authentication.");
        }

        Assert.hasText(determinedLoginProcessingUrl,
                "loginProcessingUrl could not be determined from FormLogin or RestLogin configuration.");
        optionsBuilder.loginProcessingUrl(determinedLoginProcessingUrl); // 중복 설정일 수 있으나, 명시적 설정

        return optionsBuilder.build();
    }
}