package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ForwardAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class RestLoginConfigurer <H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, RestLoginConfigurer<H>, RestAuthenticationFilter> {

    public RestLoginConfigurer() {
        super(new RestAuthenticationFilter(), null);
    }

    @Override
    public RestLoginConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }

    public RestLoginConfigurer<H> failureForwardUrl(String forwardUrl) {
        failureHandler(new ForwardAuthenticationFailureHandler(forwardUrl));
        return this;
    }

    public RestLoginConfigurer<H> successForwardUrl(String forwardUrl) {
        successHandler(new ForwardAuthenticationSuccessHandler(forwardUrl));
        return this;
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

    @Override
    public void init(H http) throws Exception {

        super.init(http);

        /*RestAuthenticationFilter filter = getAuthenticationFilter();
        AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

        if (manager != null) {
            filter.setAuthenticationManager(manager);
        }*/
    }
}

