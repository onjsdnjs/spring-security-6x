package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.OttAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

public interface OttDslConfigurer extends AuthenticationFactorConfigurer<OttOptions, OttAsepAttributes, OttDslConfigurer> {

    OttDslConfigurer defaultSubmitPageUrl(String url);
    OttDslConfigurer tokenGeneratingUrl(String url);
    OttDslConfigurer showDefaultSubmitPage(boolean show);
    OttDslConfigurer tokenService(OneTimeTokenService service);
    OttDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler);
}

