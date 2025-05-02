package io.springsecurity.springsecurity6x.security.init;

import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import io.springsecurity.springsecurity6x.security.init.configurer.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.init.configurer.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.init.configurer.StateConfigurer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * DSL 기반 인증 설정을 바탕으로 SecurityFilterChain을 Bean 으로 등록하는 최종 빌더.
 */
public class IdentityPlatformBuilder implements BeanDefinitionRegistryPostProcessor {

    private final IdentityDslRegistry registry;
    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final JwtStateConfigurerImpl jwtConfigurer;
    private final SessionStateConfigurerImpl sessionConfigurer;

    public IdentityPlatformBuilder(
            IdentityDslRegistry registry,
            ObjectProvider<HttpSecurity> httpSecurityProvider,
            JwtStateConfigurerImpl jwtConfigurer,
            SessionStateConfigurerImpl sessionConfigurer
    ) {
        this.registry = registry;
        this.httpSecurityProvider = httpSecurityProvider;
        this.jwtConfigurer = jwtConfigurer;
        this.sessionConfigurer = sessionConfigurer;
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
        IdentityConfig config = this.registry.config();

        try {
            int count = 1;
            for (AuthenticationConfig auth : config.getAuthentications()) {
                HttpSecurity http = httpSecurityProvider.getObject();

                // 1. 인증 방식에 따른 matcher 설정 위임
                ((AuthConfigurer) auth.options()).configure(http);

                // 2. 상태 전략에 따른 설정 적용
                getStateConfigurer(auth.stateType()).apply(http);

                // 3. 사용자 지정 커스터마이저 적용
                if (auth.customizer() != null) {
                    auth.customizer().customize(http);
                }

                // 4. 필터 체인 생성 및 등록
                SecurityFilterChain chain = http.build();
                String beanName = "securityFilterChain_" + count++;
                BeanDefinitionBuilder bldr = BeanDefinitionBuilder
                        .genericBeanDefinition(SecurityFilterChain.class, () -> chain)
                        .setLazyInit(false);
                registry.registerBeanDefinition(beanName, bldr.getBeanDefinition());
            }
        } catch (Exception e) {
            throw new RuntimeException("SecurityFilterChain 등록 실패", e);
        }
    }

    private StateConfigurer getStateConfigurer(String stateType) {
        return StateType.JWT.name().toLowerCase().equals(stateType)
                ? new JwtStateConfigurer(jwtConfigurer)
                : new SessionStateConfigurer(sessionConfigurer);
    }
    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        // 필요 없음
    }
}
