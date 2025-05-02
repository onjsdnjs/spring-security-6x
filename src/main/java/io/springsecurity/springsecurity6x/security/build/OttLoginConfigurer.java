package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.build.option.OttOptions;
import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class OttLoginConfigurer implements IdentitySecurityConfigurer {

    private OneTimeTokenService tokenService = new InMemoryOneTimeTokenService();

    @Override
    public boolean supports(AuthenticationConfig config) {
        return "ott".equals(config.type());
    }

    @Override
    public void configure(HttpSecurity http, AuthenticationConfig config) throws Exception {
        OttOptions options = (OttOptions) config.options();
        if (options.matchers() != null && !options.matchers().isEmpty()) {
            http.securityMatcher(options.matchers().toArray(new String[0]));
        }
        http.oneTimeTokenLogin(ott -> {
            ott
                .defaultSubmitPageUrl(options.defaultSubmitPageUrl())
                .loginProcessingUrl(options.loginProcessingUrl())
                .showDefaultSubmitPage(options.showDefaultSubmitPage())
                .tokenGeneratingUrl(options.tokenGeneratingUrl())
                .tokenService(options.tokenService());

            if (options.tokenGenerationSuccessHandler() != null) {
                ott.tokenGenerationSuccessHandler(options.tokenGenerationSuccessHandler());
            } else {
//                ott.authenticationSuccessHandler(authenticationHandlers.successHandler());
            }

        });
    }

    @Override
    public int order() {
        return 0;
    }
}
