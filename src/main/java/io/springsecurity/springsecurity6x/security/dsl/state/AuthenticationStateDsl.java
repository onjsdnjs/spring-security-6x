package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.OAuth2StateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;

import javax.crypto.SecretKey;

public final class AuthenticationStateDsl {
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
        this.selected = true;
        return jwtStateConfigurer;
    }

    public OAuth2StateConfigurer oauth2() {
        assertNotSelected();
        OAuth2StateConfigurer oauth2StateConfigurer = new OAuth2StateConfigurerImpl(properties);
        this.selected = true;
        return oauth2StateConfigurer;
    }

    public SessionStateConfigurer session() {
        assertNotSelected();
        SessionStateConfigurer sessionStateConfigurer = new SessionStateConfigurerImpl(properties);
        this.selected = true;
        return sessionStateConfigurer;
    }

    private void assertNotSelected() {
        if (selected) throw new IllegalStateException("jwt(), oauth2(), session() 중 하나만 호출할 수 있습니다.");
    }
}

