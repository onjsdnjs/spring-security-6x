package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.enums.TokenIssuer;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;

import javax.crypto.SecretKey;

public final class AuthenticationStateDsl {
    private AuthenticationStateConfigurer selectedConfigurer;
    private SessionStateConfigurer sessionStateConfigurer;
    private boolean selected = false;
    private final AuthContextProperties properties;
    private final SecretKey secretKey;

    public AuthenticationStateDsl(AuthContextProperties props, SecretKey key) {
        this.secretKey = key;
        this.properties = props;
    }

    public JwtStateConfigurer jwt() {
        assertNotSelected();
        JwtStateConfigurer configurer;

        if (properties.getTokenIssuer() == TokenIssuer.INTERNAL) {
            configurer = new JwtStateConfigurer(secretKey, properties);

        } else if (properties.getTokenIssuer() == TokenIssuer.AUTHORIZATION_SERVER) {
            configurer = new OAuth2StateConfigurer(properties);

        } else {
            throw new IllegalStateException("지원하지 않는 TokenIssuer입니다: " + properties.getTokenIssuer());
        }

        this.selectedConfigurer = configurer;
        this.selected = true;
        return configurer;
    }

    public SessionStateConfigurer session() {
        assertNotSelected();
        SessionStateConfigurer configurer = new SessionStateConfigurer(properties);
        this.selectedConfigurer = configurer;
        this.selected = true;
        return configurer;
    }


    public AuthenticationStateConfigurer build() {
        if (selectedConfigurer == null) {
            throw new IllegalStateException("jwt() 또는 session() 중 하나는 반드시 설정해야 합니다.");
        }
        return selectedConfigurer;
    }

    private void assertNotSelected() {
        if (selected) {
            throw new IllegalStateException("jwt() 또는 session()은 한 번만 호출할 수 있습니다.");
        }
    }
}

