package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.*;

/**
 * IdentitySecurityBuilder는 DSL로부터 수집된 AuthenticationConfig를 기반으로
 * HttpSecurity를 초기화하고, 각 Configurer를 순차 적용하여 SecurityFilterChain을 생성한다.
 * 이 클래스는 Spring Security의 AbstractConfiguredSecurityBuilder 철학을 따르도록 리팩토링되었다.
 */
@Slf4j
public class IdentitySecurityBuilder {

    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final List<AuthenticationConfig> authenticationConfigs;
    private final List<IdentitySecurityConfigurer> configurers;

    private final List<HttpSecurity> httpList = new ArrayList<>();
    private final Map<HttpSecurity, AuthenticationConfig> contextMap = new LinkedHashMap<>();
    private BuildState buildState = BuildState.INITIALIZING;

    public IdentitySecurityBuilder(ObjectProvider<HttpSecurity> httpSecurityProvider,
                                   List<AuthenticationConfig> authenticationConfigs,
                                   List<IdentitySecurityConfigurer> configurers) {
        this.httpSecurityProvider = httpSecurityProvider;
        this.authenticationConfigs = authenticationConfigs;
        this.configurers = configurers;
    }

    public List<SecurityFilterChain> build() throws Exception {
        synchronized (this.configurers) {
            this.buildState = BuildState.INITIALIZING;
            beforeInit();
            init();
            this.buildState = BuildState.CONFIGURING;
            beforeConfigure();
            configure();
            this.buildState = BuildState.BUILDING;
            List<SecurityFilterChain> result = performBuild();
            this.buildState = BuildState.BUILT;
            return result;
        }
    }

    protected void beforeInit() {
        log.debug("[INIT] 초기화 시작 - 인증 전략 수: {}", authenticationConfigs.size());
    }

    protected void init() throws Exception {
        int index = 1;
        for (AuthenticationConfig config : authenticationConfigs) {
            HttpSecurity http = httpSecurityProvider.getObject();
            httpList.add(http);
            contextMap.put(http, config);
            log.debug("    └─ [{}] HttpSecurity 초기화 완료 - 타입: {}, 상태: {}", index++, config.type(), config.stateType());

            for (IdentitySecurityConfigurer configurer : configurers) {
                if (configurer.supports(config)) {
                    configurer.init(http);
                }
            }
        }
    }

    protected void beforeConfigure() {
        log.debug("[CONFIGURE] Configurer 구성 준비 시작");
    }

    protected void configure() throws Exception {
        configurers.sort(Comparator.comparingInt(IdentitySecurityConfigurer::order));

        int index = 1;
        for (HttpSecurity http : httpList) {
            AuthenticationConfig config = contextMap.get(http);
            log.debug("\n● [{}] 인증 방식: {}, 상태 전략: {}", index, config.type(), config.stateType());
            Set<Class<?>> applied = new HashSet<>();

            for (IdentitySecurityConfigurer configurer : configurers) {
                if (configurer.supports(config)) {
                    Class<?> configurerType = configurer.getClass();
                    if (applied.contains(configurerType)) {
                        throw new IllegalStateException("Configurer 중복 적용 감지: " + configurerType.getSimpleName());
                    }
                    log.debug("    ├─ Configurer 적용: {} (order={})", configurerType.getSimpleName(), configurer.order());
                    configurer.configure(http, config);
                    applied.add(configurerType);
                }
            }
            index++;
        }
    }

    protected List<SecurityFilterChain> performBuild() throws Exception {
        List<SecurityFilterChain> result = new ArrayList<>();
        int index = 1;
        for (HttpSecurity http : httpList) {
            SecurityFilterChain chain = http.build();
            log.debug("    └─ [{}] SecurityFilterChain 빌드 완료", index++);
            result.add(chain);
        }
        log.info("\n[IdentitySecurityBuilder] 총 {}개의 SecurityFilterChain 빌드 완료\n", result.size());
        return result;
    }

    public BuildState state() {
        return buildState;
    }

    public enum BuildState {
        INITIALIZING,
        CONFIGURING,
        BUILDING,
        BUILT
    }
}


