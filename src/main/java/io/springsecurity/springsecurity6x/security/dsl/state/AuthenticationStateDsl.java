package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.transport.HeaderTokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import org.springframework.context.ApplicationContext;

import javax.crypto.SecretKey;

public final class AuthenticationStateDsl {
    private JwtStateStrategy jwtStrategy;
    private SessionStateStrategy sessionStrategy;
    private boolean selected = false;
    private final AuthContextProperties properties;
    private final SecretKey secretKey;

    public AuthenticationStateDsl(ApplicationContext applicationContext) {
        properties = applicationContext.getBean(AuthContextProperties.class);
        secretKey = applicationContext.getBean(SecretKey.class);
    }

    public JwtStateStrategy jwt() {
        assertNotSelected();

        this.jwtStrategy = new JwtStateStrategy(secretKey, properties);
        this.selected = true;
        return jwtStrategy;
    }

    public SessionStateStrategy session() {
        assertNotSelected();
        this.sessionStrategy = new SessionStateStrategy(properties);
        this.selected = true;
        return sessionStrategy;
    }

    public AuthenticationStateStrategy build() {
        if (jwtStrategy != null) {
            return jwtStrategy;

        } else if (sessionStrategy != null) {
            return sessionStrategy;

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

