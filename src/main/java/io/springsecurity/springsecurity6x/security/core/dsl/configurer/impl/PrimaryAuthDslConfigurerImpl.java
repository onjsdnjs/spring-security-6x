package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import org.springframework.context.ApplicationContext; // AuthMethodConfigurerFactory 사용 위해 필요할 수 있음
import org.springframework.security.config.Customizer;
import org.springframework.util.Assert;

public class PrimaryAuthDslConfigurerImpl implements PrimaryAuthDslConfigurer {

    private Customizer<FormDslConfigurer> formLoginCustomizer;
    private Customizer<RestDslConfigurer> restLoginCustomizer;
    private ApplicationContext applicationContext; // AuthMethodConfigurerFactory 사용 위해 (선택적)

    // AuthMethodConfigurerFactory를 사용하려면 ApplicationContext가 필요할 수 있으므로 생성자 수정 가능
    public PrimaryAuthDslConfigurerImpl() {
    }
    // 예시: public PrimaryAuthDslConfigurerImpl(ApplicationContext context) { this.applicationContext = context; }


    @Override
    public PrimaryAuthDslConfigurer formLogin(Customizer<FormDslConfigurer> formLoginCustomizer) {
        this.formLoginCustomizer = formLoginCustomizer;
        this.restLoginCustomizer = null;
        return this;
    }

    @Override
    public PrimaryAuthDslConfigurer restLogin(Customizer<RestDslConfigurer> restLoginCustomizer) {
        this.restLoginCustomizer = restLoginCustomizer;
        this.formLoginCustomizer = null;
        return this;
    }

    @Override
    public PrimaryAuthenticationOptions buildOptions() {
        PrimaryAuthenticationOptions.Builder optionsBuilder = PrimaryAuthenticationOptions.builder();
        String determinedLoginProcessingUrl;

        if (formLoginCustomizer != null) {
            FormDslConfigurerImpl formDslBuilder = new FormDslConfigurerImpl(); // 직접 생성 또는 팩토리 통해
            formLoginCustomizer.customize(formDslBuilder);
            FormOptions builtFormOptions = formDslBuilder.buildConcreteOptions();
            optionsBuilder.formOptions(builtFormOptions);
            determinedLoginProcessingUrl = builtFormOptions.getLoginProcessingUrl();

        } else if (restLoginCustomizer != null) {
            RestDslConfigurerImpl restDslBuilder = new RestDslConfigurerImpl(); // 직접 생성 또는 팩토리 통해
            restLoginCustomizer.customize(restDslBuilder);
            RestOptions builtRestOptions = restDslBuilder.buildConcreteOptions();
            optionsBuilder.restOptions(builtRestOptions);
            determinedLoginProcessingUrl = builtRestOptions.getLoginProcessingUrl(); // getProcessingUrl() 사용
        } else {
            throw new DslConfigurationException("Either formLogin or restLogin must be configured for primary authentication.");
        }

        Assert.hasText(determinedLoginProcessingUrl,
                "loginProcessingUrl could not be determined from FormLogin or RestLogin configuration.");
        // PrimaryAuthenticationOptions.Builder 에서 loginProcessingUrl을 설정하는 로직은
        // formOptions() 또는 restOptions() 내부에서 자동으로 처리되도록 수정하는 것이 더 좋음 (PrimaryAuthenticationOptions.Builder 수정 참고)
        // 여기서는 명시적으로 한번 더 설정 (PrimaryAuthenticationOptions.Builder가 이를 허용해야 함)
        optionsBuilder.loginProcessingUrl(determinedLoginProcessingUrl);


        return optionsBuilder.build();
    }
}