package io.springsecurity.springsecurity6x.security.dsl.state;

import org.springframework.context.ApplicationContext;

public final class AuthenticationStateDsl {
    private final ApplicationContext applicationContext;
    private JwtStateStrategy jwtStrategy;
    private SessionStateStrategy sessionStrategy;
    private boolean selected = false;

    public AuthenticationStateDsl(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public JwtStateStrategy jwt() {
        assertNotSelected();
        this.jwtStrategy = new JwtStateStrategy(applicationContext);
        this.selected = true;
        return jwtStrategy;
    }

    public SessionStateStrategy session() {
        assertNotSelected();
        this.sessionStrategy = new SessionStateStrategy(applicationContext);
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

