package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * IdentitySecurityBuilder는 DSL로부터 수집된 AuthenticationConfig를 기반으로
 * HttpSecurity를 초기화하고, 각 Configurer를 순차 적용하여 SecurityFilterChain을 생성한다.
 * 이 클래스는 POJO로 유지되어 전체 인증 초기화 과정을 명확하게 통제할 수 있다.
 */
@Slf4j
public class IdentitySecurityBuilder {

    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final List<AuthenticationConfig> authenticationConfigs;
    private final List<IdentitySecurityConfigurer> configurers;

    public IdentitySecurityBuilder(ObjectProvider<HttpSecurity> httpSecurityProvider,
                                   List<AuthenticationConfig> authenticationConfigs,
                                   List<IdentitySecurityConfigurer> configurers) {
        this.httpSecurityProvider = httpSecurityProvider;
        this.authenticationConfigs = authenticationConfigs;
        this.configurers = configurers;
    }

    /**
     * SecurityFilterChain 리스트만 반환하며, FilterChainProxy는 Spring 내부에서 관리되도록 위임한다.
     */
    public List<SecurityFilterChain> buildSecurityFilterChains() throws Exception {
        int index = 1;
        List<SecurityFilterChain> result = new ArrayList<>();

        for (AuthenticationConfig config : authenticationConfigs) {
            HttpSecurity http = httpSecurityProvider.getObject();
            log.info("[{}] 인증 구성 시작: {} / {}", index, config.type(), config.stateType());

            Set<Class<?>> applied = new HashSet<>();

            for (IdentitySecurityConfigurer configurer : configurers) {
                if (configurer.supports(config)) {
                    Class<?> configurerType = configurer.getClass();
                    if (applied.contains(configurerType)) {
                        throw new IllegalStateException("Configurer 중복 적용 감지: " + configurerType.getSimpleName());
                    }
                    log.info("    |- Configurer 적용: {}", configurerType.getSimpleName());
                    configurer.configure(http, config);
                    applied.add(configurerType);
                }
            }

            SecurityFilterChain chain = http.build();
            result.add(chain);
            log.info("[{}] SecurityFilterChain 생성 완료", index++);
        }

        log.info("[완료] SecurityFilterChain 리스트 생성 완료");
        return result;
    }
}