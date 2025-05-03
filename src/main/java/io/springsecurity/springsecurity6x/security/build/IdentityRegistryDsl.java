/*
package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.core.feature.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.feature.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.feature.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.core.feature.option.RestOptions;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.security.config.Customizer;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.List;

*/
/**
 * IdentityDslRegistry는 DSL 기반으로 인증 설정을 수집하고 IdentitySecurityBuilder를 통해 빌드 트리거를 제공한다.
 *//*

public class IdentityRegistryDsl {

    private final List<AuthenticationConfig> authenticationConfigs = new ArrayList<>();
    private final List<IdentitySecurityConfigurer> configurers = new ArrayList<>();
    private SecretKey secretKey;
    private AuthContextProperties props;

    public IdentityStateDsl form(Customizer<FormOptions> customizer) {
        FormOptions options = new FormOptions();
        customizer.customize(options);
        configurers.add(new FormLoginConfigurer());
        return state -> {
            authenticationConfigs.add(new AuthenticationConfig(AuthType.FORM.name().toLowerCase(), options, state.name().toLowerCase(), null));
            registerStateConfigurer(state);
            return this;
        };
    }

    public IdentityStateDsl rest(Customizer<RestOptions> customizer) {
        RestOptions options = new RestOptions();
        customizer.customize(options);
        configurers.add(new RestLoginConfigurer());
        return state -> {
            authenticationConfigs.add(new AuthenticationConfig(AuthType.REST.name().toLowerCase(), options, state.name().toLowerCase(), null));
            registerStateConfigurer(state);
            return this;
        };
    }

    public IdentityStateDsl ott(Customizer<OttOptions> customizer) {
        OttOptions options = new OttOptions();
        customizer.customize(options);
        configurers.add(new OttLoginConfigurer());
        return state -> {
            authenticationConfigs.add(new AuthenticationConfig(AuthType.OTT.name().toLowerCase(), options, state.name().toLowerCase(), null));
            registerStateConfigurer(state);
            return this;
        };
    }

    public IdentityStateDsl passkey(Customizer<PasskeyOptions> customizer) {
        PasskeyOptions options = new PasskeyOptions();
        customizer.customize(options);
        configurers.add(new PasskeyLoginConfigurer());
        return state -> {
            authenticationConfigs.add(new AuthenticationConfig(AuthType.PASSKEY.name().toLowerCase(), options, state.name().toLowerCase(), null));
            registerStateConfigurer(state);
            return this;
        };
    }

    public List<AuthenticationConfig> config() {
        return authenticationConfigs;
    }

    public List<IdentitySecurityConfigurer> configurerList() {
        return configurers;
    }

    private void registerStateConfigurer(StateType state) {
        switch (state) {
            case JWT -> configurers.add(new JwtStateConfigurerImpl(secretKey, props));
            case SESSION -> configurers.add(new SessionStateConfigurerImpl(props));
        }
    }

    public interface IdentityStateDsl {
        IdentityRegistryDsl use(StateType state);

        default IdentityRegistryDsl useJwt() {
            return use(StateType.JWT);
        }

        default IdentityRegistryDsl useSession() {
            return use(StateType.SESSION);
        }
    }
}
*/
