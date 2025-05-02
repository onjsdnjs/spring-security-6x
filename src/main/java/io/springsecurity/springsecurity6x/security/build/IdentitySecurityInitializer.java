package io.springsecurity.springsecurity6x.security.build;

public class IdentitySecurityInitializer {

    private final IdentitySecurityBuilder builder;

    public IdentitySecurityInitializer(IdentitySecurityBuilder builder) {
        this.builder = builder;
    }

    public void init() {
        try {
            builder.buildSecurityFilterChains();
        } catch (Exception e) {
            throw new IllegalStateException("Security 초기화 실패", e);
        }
    }
}

