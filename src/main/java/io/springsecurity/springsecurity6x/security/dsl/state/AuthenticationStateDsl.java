package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;

import javax.crypto.SecretKey;

public final class AuthenticationStateDsl {
    private JwtStateConfigurer jwtStateConfigurer;
    private SessionStateConfigurer sessionStateConfigurer;
    private boolean selected = false;
    private final AuthContextProperties properties;
    private final SecretKey secretKey;

    public AuthenticationStateDsl(ApplicationContext applicationContext) {
        properties = applicationContext.getBean(AuthContextProperties.class);
        secretKey = applicationContext.getBean(SecretKey.class);
    }

    public JwtStateConfigurer jwt() {
        assertNotSelected();

        this.jwtStateConfigurer = new JwtStateConfigurer(secretKey, properties);
        this.selected = true;
        return jwtStateConfigurer;
    }

    public SessionStateConfigurer session() {
        assertNotSelected();
        this.sessionStateConfigurer = new SessionStateConfigurer(properties);
        this.selected = true;
        return sessionStateConfigurer;
    }

    public AuthenticationStateConfigurer build() {
        if (jwtStateConfigurer != null) {
            return jwtStateConfigurer;

        } else if (sessionStateConfigurer != null) {
            return sessionStateConfigurer;

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

