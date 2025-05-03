package io.springsecurity.springsecurity6x.security.core;

import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class RestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, RestAuthenticationConfigurer<H>, RestAuthenticationFilter> {

    public RestAuthenticationConfigurer() {
        super(new RestAuthenticationFilter(), null);
    }

    @Override
    public RestAuthenticationConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }
}