package io.springsecurity.springsecurity6x.security.init;

public class IdentityConfigurerBinder {

    private final IdentityConfig config;

    public IdentityConfigurerBinder(IdentityConfig config) {
        this.config = config;
    }

    public void bind() {
        for (AuthenticationConfig entry : config.getAuthentications()) {
            String type = entry.type();
            String stateType = entry.stateType();
            Object options = entry.options();

            System.out.printf("[바인딩] 인증 방식: %s, 상태 전략: %s, 옵션 타입: %s%n",
                    type, stateType, options.getClass().getSimpleName());
        }
    }
}