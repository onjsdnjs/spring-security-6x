package io.springsecurity.springsecurity6x.security.postprocesor;

import io.springsecurity.springsecurity6x.security.builder.PlatformSecurityChainBuilder;
import io.springsecurity.springsecurity6x.security.dsl.authentication.multi.IdentityDsl;
import io.springsecurity.springsecurity6x.security.dsl.authentication.multi.IdentityDslImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

public class DynamicSecurityRegistrar implements BeanDefinitionRegistryPostProcessor {

    private final IdentityDslImpl dsl;
    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final JwtStateConfigurerImpl jwtConfigurer;
    private final SessionStateConfigurerImpl sessionConfigurer;

    public DynamicSecurityRegistrar(IdentityDsl identityDsl,
                                    ObjectProvider<HttpSecurity> httpSecurityProvider,
                                    SecretKey key,
                                    AuthContextProperties props) {
        this.dsl = (IdentityDslImpl) identityDsl;
        this.httpSecurityProvider = httpSecurityProvider;
        this.jwtConfigurer = new JwtStateConfigurerImpl(key, props);
        this.sessionConfigurer = new SessionStateConfigurerImpl(props);
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        PlatformSecurityChainBuilder builder = new PlatformSecurityChainBuilder(httpSecurityProvider, jwtConfigurer, sessionConfigurer);

        int order = 1;
        for (var authConfig : dsl.getConfig().authentications) {
            String name = "securityFilterChain_" + authConfig.type + "_" + order;

            BeanDefinitionBuilder bldr = BeanDefinitionBuilder.genericBeanDefinition(SecurityFilterChain.class, () -> {
                        try {
                            return builder.buildChain(authConfig);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .setLazyInit(false);

            registry.registerBeanDefinition(name, bldr.getBeanDefinition());
            order++;
        }
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // not needed
    }
}
