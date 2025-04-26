package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;

public final class AuthenticationStateDsl {
    private JwtStateStrategy jwtStrategy;
    private SessionStateStrategy sessionStrategy;
    private boolean selected = false;

    public JwtStateStrategy jwt(TokenService ts) {
        assertNotSelected();
        this.jwtStrategy = new JwtStateStrategy(ts);
        this.selected = true;
        return jwtStrategy;
    }

    public SessionStateStrategy session() {
        assertNotSelected();
        this.sessionStrategy = new SessionStateStrategy();
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

