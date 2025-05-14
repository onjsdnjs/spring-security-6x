package io.springsecurity.springsecurity6x.security.core.dsl.factor.ott;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.mfa.options.OttFactorOptions;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

public interface OttFactorDslConfigurer extends OptionsBuilderDsl<OttFactorOptions, OttFactorDslConfigurer> {
    OttFactorDslConfigurer processingUrl(String url);
    OttFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler);
    OttFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler);
    OttFactorDslConfigurer tokenService(OneTimeTokenService oneTimeTokenService);
    OttFactorDslConfigurer tokenServiceBeanName(String beanName);
    OttFactorDslConfigurer tokenGeneratingUrl(String url);
    OttFactorDslConfigurer defaultSubmitPageUrl(String url);
    OttFactorDslConfigurer showDefaultSubmitPage(boolean show);
    OttFactorDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler); // from OttOptions
}