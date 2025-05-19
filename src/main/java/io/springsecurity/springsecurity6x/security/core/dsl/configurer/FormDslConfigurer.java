package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.FormAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import org.springframework.security.config.Customizer;

public interface FormDslConfigurer
        extends AuthenticationFactorConfigurer<FormOptions, FormAsepAttributes, FormDslConfigurer> { // S를 FormDslConfigurer로 명시

    FormDslConfigurer loginPage(String loginPageUrl);
    FormDslConfigurer usernameParameter(String usernameParameter);
    FormDslConfigurer passwordParameter(String passwordParameter);
    FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse);
    FormDslConfigurer failureUrl(String failureUrl);
    FormDslConfigurer permitAll();
    FormDslConfigurer rawFormLogin(SafeHttpFormLoginCustomizer customizer);

    @Override
    FormDslConfigurer asep(Customizer<FormAsepAttributes> formAsepAttributesCustomizer) throws Exception;
}