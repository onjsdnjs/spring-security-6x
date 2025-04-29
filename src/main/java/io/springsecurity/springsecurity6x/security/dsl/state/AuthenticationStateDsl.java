package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.OAuth2StateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.enums.TokenIssuer;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;

import javax.crypto.SecretKey;

public final class AuthenticationStateDsl {
    private AuthenticationStateConfigurer selectedConfigurer;
    private SessionStateConfigurerImpl sessionStateConfigurerImpl;
    private boolean selected = false;
    private final AuthContextProperties properties;
    private final SecretKey secretKey;

    public AuthenticationStateDsl(AuthContextProperties props, SecretKey key) {
        this.secretKey = key;
        this.properties = props;
    }

    public JwtStateConfigurer jwt() {
        assertNotSelected();
        JwtStateConfigurer jwtStateConfigurer = new JwtStateConfigurerImpl(secretKey, properties);
        this.selectedConfigurer = jwtStateConfigurer;
        return jwtStateConfigurer;
    }

    public OAuth2StateConfigurer oauth2() {
        assertNotSelected();
        OAuth2StateConfigurer oauth2StateConfigurer = new OAuth2StateConfigurerImpl(properties);
        this.selectedConfigurer = oauth2StateConfigurer;
        return oauth2StateConfigurer;
    }

    public SessionStateConfigurer session() {
        assertNotSelected();
        SessionStateConfigurer sessionStateConfigurer = new SessionStateConfigurerImpl(properties);
        this.selectedConfigurer = sessionStateConfigurer;
        return sessionStateConfigurer;
    }


    public AuthenticationStateConfigurer build() {
        if (selectedConfigurer != null) {
            return selectedConfigurer;
        } else if (sessionStateConfigurerImpl != null) {
            return sessionStateConfigurerImpl;
        } else {
            throw new IllegalStateException("jwt() 또는 session() 중 하나는 반드시 설정해야 합니다.");
        }
    }

    private void assertNotSelected() {
        if (selected) {
            throw new IllegalStateException("jwt() 또는 session()은 한 번만 호출할 수 있습니다.");
        }
    }
}

