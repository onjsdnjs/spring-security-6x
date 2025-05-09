/*
package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.FormDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.RestDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.feature.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

public class IdentityDslRegistry2 implements SecurityPlatformDsl {

    private final PlatformConfig.Builder platformBuilder = PlatformConfig.builder();

    private SecurityPlatformDsl originGlobal(Customizer<HttpSecurity> customizer){
        platformBuilder.global(customizer);
        return this;
    }

    @Override
    public SecurityPlatformDsl global(SafeHttpCustomizer customizer) {
        return originGlobal(wrapSafe(customizer));
    }

    private Customizer<HttpSecurity> wrapSafe(SafeHttpCustomizer safe) {
        return http -> {
            try {
                safe.customize(http);
            } catch (Exception e) {
                System.err.println("Global customizer exception: " + e.getMessage());
            }
        };
    }

    @Override
    public IdentityStateDsl form(Customizer<FormDslConfigurer> customizer) {

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        FormDslConfigurerImpl impl = new FormDslConfigurerImpl(stepConfig);
        customizer.customize(impl);
        AuthenticationStepConfig step = impl.toConfig();

        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder(
                        AuthType.FORM.name().toLowerCase()
                )
                .stepConfigs(List.of(step))
                .stateConfig(null)                    // StateSetter 에서 채움
                .customizer(http -> {})     // Flow-level customizer 없음
                .order(impl.order())
                .build();

        platformBuilder.addFlow(flow);

        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer) {

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        RestDslConfigurerImpl impl = new RestDslConfigurerImpl(stepConfig);
        customizer.customize(impl);
        AuthenticationStepConfig step = impl.toConfig();

        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder(
                        AuthType.REST.name().toLowerCase()
                )
                .stepConfigs(List.of(step))
                .stateConfig(null)                     // StateSetter 에서 채움
                .customizer(http -> {})      // Flow-level customizer 없음
                .order(impl.order())
                .build();

        platformBuilder.addFlow(flow);

        return new StateSetter(this);
    }
    */
/*
    @Override
    public IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer) {
        OttDslConfigurerImpl impl = new OttDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.OTT.name().toLowerCase(),
                List.of(impl.toConfig()),
                null,
                http -> {}
        ));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer) {
        PasskeyDslConfigurerImpl impl = new PasskeyDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.PASSKEY.name().toLowerCase(),
                List.of(impl.toConfig()),
                null,
                http -> {}
        ));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) {
        MfaDslConfigurerImpl impl = new MfaDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.MFA.name().toLowerCase(),
                impl.getAuthConfigs(),
                null,
                http -> {}
        ));
        return new StateSetter(this);
    }*//*


    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }

    private record StateSetter(IdentityDslRegistry2 registry) implements IdentityStateDsl {

        @Override
            public SecurityPlatformDsl session(Customizer<SessionStateConfigurer> customizer) {
                registry.setLastState(StateType.SESSION.name().toLowerCase());
                return registry;
            }

            @Override
            public SecurityPlatformDsl jwt(Customizer<JwtStateConfigurer> customizer) {
                registry.setLastState(StateType.JWT.name().toLowerCase());
                return registry;
            }

            @Override
            public SecurityPlatformDsl oauth2(Customizer<OAuth2StateConfigurer> customizer) {
                registry.setLastState(StateType.OAUTH2.name().toLowerCase());
                return registry;
            }
        }

    private void setLastState(String stateId) {
        var flow = config.flows().getLast();
        flow.stateConfig(new StateConfig(stateId));
    }
}
*/
