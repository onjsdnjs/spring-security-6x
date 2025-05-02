package io.springsecurity.springsecurity6x.security.dsl.authentication.single;

import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

public final class OttAuthenticationDsl extends AbstractAuthenticationDsl {
    private String loginProcessingUrl = "/login/ott";
    private String defaultSubmitPageUrl = "/login/ott";
    private String tokenGeneratingUrl = "/ott/generate";
    private boolean showDefaultSubmitPage = true;
    private OneTimeTokenService tokenService = new InMemoryOneTimeTokenService();
    private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

    public OttAuthenticationDsl loginProcessingUrl(String url) { this.loginProcessingUrl = url; return this; }
    public OttAuthenticationDsl defaultSubmitPageUrl(String url) { this.defaultSubmitPageUrl = url; return this; }
    public OttAuthenticationDsl tokenGeneratingUrl(String url) { this.tokenGeneratingUrl = url; return this; }
    public OttAuthenticationDsl showDefaultSubmitPage(boolean show) { this.showDefaultSubmitPage = show; return this; }
    public OttAuthenticationDsl tokenService(OneTimeTokenService s) { this.tokenService = s; return this; }
    public OttAuthenticationDsl tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler h) { this.tokenGenerationSuccessHandler = h; return this; }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.oneTimeTokenLogin(ott -> {
            ott
                    .defaultSubmitPageUrl(defaultSubmitPageUrl)
                    .loginProcessingUrl(loginProcessingUrl)
                    .showDefaultSubmitPage(showDefaultSubmitPage)
                    .tokenGeneratingUrl(tokenGeneratingUrl)
                    .tokenService(tokenService);

            if (tokenGenerationSuccessHandler != null) {
                ott.tokenGenerationSuccessHandler(tokenGenerationSuccessHandler);
            } else {
                ott.authenticationSuccessHandler(authenticationHandlers.successHandler());
            }

        });
    }
}
