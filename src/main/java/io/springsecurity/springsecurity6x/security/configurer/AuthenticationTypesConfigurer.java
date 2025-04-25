package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.authentication.ApiAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.AuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.OttAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.PasskeyAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class AuthenticationTypesConfigurer extends AbstractHttpConfigurer<AuthenticationTypesConfigurer, HttpSecurity> {

    private final Map<Class<? extends AuthenticationConfigurer>, AuthenticationConfigurer> entries = new LinkedHashMap<>();
    private boolean configured = false;

    /** Form 인증 */
    public AuthenticationTypesConfigurer form(Customizer<ApiAuthenticationConfigurer> customizer) {
        return add(ApiAuthenticationConfigurer.class, new ApiAuthenticationConfigurer(), customizer);
    }

    /** OTT 인증 */
    public AuthenticationTypesConfigurer ott(Customizer<OttAuthenticationConfigurer> customizer) {
        return add(OttAuthenticationConfigurer.class, new OttAuthenticationConfigurer(), customizer);
    }

    /** Passkey(WebAuthn) 인증 */
    public AuthenticationTypesConfigurer passkey(Customizer<PasskeyAuthenticationConfigurer> customizer) {
        return add(PasskeyAuthenticationConfigurer.class, new PasskeyAuthenticationConfigurer(), customizer);
    }

    private <T extends AuthenticationConfigurer> AuthenticationTypesConfigurer add(Class<T> type, T configurer, Customizer<T> customizer) {
        if (configured) {
            throw new IllegalStateException("이미 인증 타입이 설정되었습니다.");
        }
        if (entries.containsKey(type)) {
            throw new IllegalStateException(type.getSimpleName() + "는 이미 한 번 설정되었습니다.");
        }

        customizer.customize(configurer);
        entries.put(type, configurer);
        return this;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        builder.setSharedObject(AuthenticationTypesConfigurer.class, this);
        configured = true;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        /*AuthenticationTypesConfigurer types = http.getSharedObject(AuthenticationTypesConfigurer.class);
        AuthenticationStateStrategy stateStrategy = http.getSharedObject(AuthenticationStateStrategy.class);
        for (AuthenticationConfigurer cfg : types.entries()) {
            cfg.stateStrategy(stateStrategy);
            cfg.configure(http);
        }*/
    }

    public List<AuthenticationConfigurer> entries() {
        return entries.values().stream().toList();
    }
}

