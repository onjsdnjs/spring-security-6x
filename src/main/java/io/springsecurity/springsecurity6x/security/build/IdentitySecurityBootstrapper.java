package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * IdentitySecurityBootstrapper
 *
 * IdentitySecurityBuilder를 기반으로 전체 보안 구성을 실행하고,
 * 최종적으로 SecurityFilterChain을 생성하여 FilterChainProxy가 감지 가능하게 한다.
 * 주입된 구성 정보와 Configurer들을 통해 실제 빌드 프로세스를 트리거하는 책임을 갖는다.
 */
@Slf4j
public class IdentitySecurityBootstrapper {

    private final IdentitySecurityBuilder builder;

    public IdentitySecurityBootstrapper(
            ObjectProvider<HttpSecurity> httpSecurityProvider,
            List<AuthenticationConfig> authenticationConfigs,
            List<IdentitySecurityConfigurer> configurers
    ) {
        this.builder = new IdentitySecurityBuilder(httpSecurityProvider, authenticationConfigs, configurers);
    }

    /**
     * 전체 보안 초기화 프로세스를 실행하고 SecurityFilterChain 목록을 반환한다.
     */
    public List<SecurityFilterChain> initialize() {
        try {
            log.info("IdentitySecurityBootstrapper 초기화 시작");
            List<SecurityFilterChain> chains = builder.buildSecurityFilterChains();
            log.info("IdentitySecurityBootstrapper 초기화 완료");
            return chains;
        } catch (Exception e) {
            log.error("SecurityFilterChain 초기화 실패", e);
            throw new IllegalStateException("SecurityFilterChain 초기화 중 예외 발생", e);
        }
    }

    public IdentitySecurityBuilder.BuildState getState() {
        return builder.state();
    }
}


