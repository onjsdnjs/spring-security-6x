package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.CommonSecurityDsl;

public interface OttDslConfigurer extends CommonSecurityDsl<OttDslConfigurer> {

    OttDslConfigurer loginProcessingUrl(String url);

    OttDslConfigurer targetUrl(String url);

    OttDslConfigurer defaultSubmitPageUrl(String url);

    OttDslConfigurer tokenGeneratingUrl(String url);

    OttDslConfigurer showDefaultSubmitPage(boolean show);

    OttDslConfigurer tokenService(org.springframework.security.authentication.ott.OneTimeTokenService service);

    OttDslConfigurer tokenGenerationSuccessHandler(org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler handler);
}

