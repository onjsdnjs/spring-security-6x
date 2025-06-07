package io.springsecurity.springsecurity6x.security.manager;

import io.springsecurity.springsecurity6x.security.factory.ExpressionAuthorizationManagerResolver;
import io.springsecurity.springsecurity6x.security.service.DynamicAuthorizationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * PEP (Policy Enforcement Point): 정책 강제 지점.
 * - DB로부터 동적 인가 규칙을 로드한다.
 * - ExpressionAuthorizationManagerResolver를 통해 규칙에 맞는 스프링 시큐리티의 AuthorizationManager를 생성한다.
 * - 요청이 오면 매칭되는 Manager에게 인가 결정을 위임하고, 그 결과를 강제한다.
 */
@Slf4j
@Component("customDynamicAuthorizationManager")
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final DynamicAuthorizationService dynamicAuthorizationService;
    private final ExpressionAuthorizationManagerResolver managerResolver; // <<< Resolver 주입

    private List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

    @PostConstruct
    public void initialize() {
        this.mappings = dynamicAuthorizationService.getUrlRoleMappings().entrySet().stream()
                .map(entry -> {
                    RequestMatcher matcher = PathPatternRequestMatcher.withDefaults().matcher(entry.getKey());
                    // Resolver를 통해 가장 적합한 스프링 시큐리티의 Manager를 받아옴
                    AuthorizationManager<RequestAuthorizationContext> manager = managerResolver.resolve(entry.getValue());
                    return new RequestMatcherEntry<>(matcher, manager);
                })
                .collect(Collectors.toList());
        log.info("Initialized {} dynamic authorization mappings using Spring Security engines.", mappings.size());
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext request) {
        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {
            if (mapping.getRequestMatcher().matcher(request.getRequest()).isMatch()) {
                AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
                log.trace("Dispatching to '{}' for URI '{}'", manager.getClass().getSimpleName(), request.getRequest().getRequestURI());
                // 실제 인가 결정은 스프링 시큐리티의 네이티브 Manager가 수행
                return manager.check(authentication, request);
            }
        }
        return new AuthorizationDecision(false);
    }

    // reload() 메서드는 캐시를 비우고 initialize()를 다시 호출하도록 구현
    public synchronized void reload() {
        dynamicAuthorizationService.clearCache();
        initialize();
    }
}