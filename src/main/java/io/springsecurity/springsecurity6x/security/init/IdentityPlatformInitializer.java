package io.springsecurity.springsecurity6x.security.init;

import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import io.springsecurity.springsecurity6x.security.init.configurer.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.init.configurer.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.init.configurer.StateConfigurer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class IdentityPlatformInitializer implements SmartInitializingSingleton {

    private final IdentityDslRegistry registry;
    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final JwtStateConfigurerImpl jwtConfigurer;
    private final SessionStateConfigurerImpl sessionConfigurer;
    private final List<SecurityFilterChain> chains = new ArrayList<>() {
        @Override
        public SecurityFilterChain get(int index) {
            return null;
        }

        @Override
        public int size() {
            return 0;
        }
    };

    public IdentityPlatformInitializer(
            IdentityDslRegistry registry,
            ObjectProvider<HttpSecurity> httpSecurityProvider,
            JwtStateConfigurerImpl jwtConfigurer,
            SessionStateConfigurerImpl sessionConfigurer) {
        this.registry = registry;
        this.httpSecurityProvider = httpSecurityProvider;
        this.jwtConfigurer = jwtConfigurer;
        this.sessionConfigurer = sessionConfigurer;
    }

    public void afterSingletonsInstantiated() {
        IdentityConfig config = registry.config();

        log.info("\n[IdentityPlatform] 인증 플랫폼 초기화 시작");
        log.info("------------------------------------------------------------");
        log.info("총 등록된 인증 방식: {}개", config.getAuthentications().size());

        try {
            int count = 1;
            for (AuthenticationConfig auth : config.getAuthentications()) {
                log.info("[{}] 인증 방식: {} [{}]", count, auth.type().toUpperCase(), auth.stateType().toUpperCase());

                HttpSecurity http = httpSecurityProvider.getObject();

                log.info("    |- [1] Matcher 및 인증 옵션 구성 시작");
                Object options = auth.options();
                ((AuthConfigurer) options).configure(http);
                log.info("    |- [1] 구성 완료");

                log.info("    |- [2] 상태 전략 구성 시작: {}", auth.stateType());
                getStateConfigurer(auth.stateType()).apply(http);
                log.info("    |- [2] 상태 전략 적용 완료");

                SecurityFilterChain chain = http.build();
                log.info("    `- SecurityFilterChain #{} 빌드 완료", count++);
            }

            log.info("[IdentityPlatform] 모든 인증 전략 및 필터 체인 초기화 완료");
            log.info("------------------------------------------------------------\n");
        } catch (Exception e) {
            log.error("[ERROR] SecurityFilterChain 동적 생성 실패", e);
            throw new RuntimeException("SecurityFilterChain 동적 생성 실패", e);
        }
    }

    private StateConfigurer getStateConfigurer(String stateType) {
        return "jwt".equals(stateType)
                ? new JwtStateConfigurer(jwtConfigurer)
                : new SessionStateConfigurer(sessionConfigurer);
    }

    public List<SecurityFilterChain> filterChains() {
        return chains;
    }
}

