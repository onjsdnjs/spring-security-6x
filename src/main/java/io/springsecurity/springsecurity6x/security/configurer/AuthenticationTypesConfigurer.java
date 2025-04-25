package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.authentication.ApiAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.AuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.OttAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.PasskeyAuthenticationConfigurer;
import org.springframework.security.config.Customizer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class AuthenticationTypesConfigurer {

    private final Map<Class<? extends AuthenticationConfigurer>, AuthenticationConfigurer> entries = new LinkedHashMap<>();

    private <T extends AuthenticationConfigurer> AuthenticationTypesConfigurer add(Class<T> key, T instance, Customizer<T> customizer) {
        if (entries.containsKey(key)) {
            throw new IllegalStateException(key.getSimpleName() + "는 이미 한 번 설정되었습니다.");
        }
        customizer.customize(instance);
        entries.put(key, instance);
        return this;
    }

    /** Form 인증 */
    public AuthenticationTypesConfigurer form(Customizer<ApiAuthenticationConfigurer> customizer) {
        return add(
                ApiAuthenticationConfigurer.class,
                new ApiAuthenticationConfigurer(),
                customizer
        );
    }

    /** OTT 인증 */
    public AuthenticationTypesConfigurer ott(Customizer<OttAuthenticationConfigurer> customizer) {
        return add(
                OttAuthenticationConfigurer.class,
                new OttAuthenticationConfigurer(),
                customizer
        );
    }

    /** Passkey(WebAuthn) 인증 */
    public AuthenticationTypesConfigurer passkey(Customizer<PasskeyAuthenticationConfigurer> customizer) {
        return add(
                PasskeyAuthenticationConfigurer.class,
                new PasskeyAuthenticationConfigurer(),
                customizer
        );
    }

    public List<AuthenticationConfigurer> build() {
        return entries.values().stream().toList();
    }
}

