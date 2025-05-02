package io.springsecurity.springsecurity6x.security.build.option;

import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.util.List;

public class OttOptions implements AuthConfigurer {

    private List<String> matchers;
    private String loginProcessingUrl = "/login/ott";
    private String defaultSubmitPageUrl = "/login/ott";
    private String tokenGeneratingUrl = "/ott/generate";
    private boolean showDefaultSubmitPage = true;
    private OneTimeTokenService tokenService = new InMemoryOneTimeTokenService();
    private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

    public List<String> matchers() {return matchers;}
    public void matchers(List<String> matchers) {this.matchers = matchers;}
    public void loginProcessingUrl(String url) { this.loginProcessingUrl = url; }
    public void defaultSubmitPageUrl(String url) { this.defaultSubmitPageUrl = url; }
    public void tokenGeneratingUrl(String url) { this.tokenGeneratingUrl = url; }
    public void showDefaultSubmitPage(boolean show) { this.showDefaultSubmitPage = show; }
    public void tokenService(OneTimeTokenService s) { this.tokenService = s; }
    public void tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler h) { this.tokenGenerationSuccessHandler = h; }

    public String loginProcessingUrl() {
        return loginProcessingUrl;
    }

    public String defaultSubmitPageUrl() {
        return defaultSubmitPageUrl;
    }

    public String tokenGeneratingUrl() {
        return tokenGeneratingUrl;
    }

    public boolean showDefaultSubmitPage() {
        return showDefaultSubmitPage;
    }

    public OneTimeTokenService tokenService() {
        return tokenService;
    }

    public OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler() {
        return tokenGenerationSuccessHandler;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        if (matchers != null && !matchers.isEmpty()) {
            http.securityMatcher(matchers.toArray(new String[0]));
        } else {
            http.securityMatcher("/**");
        }
    }
}
