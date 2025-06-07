package io.springsecurity.springsecurity6x.security.manager;

import io.springsecurity.springsecurity6x.security.service.DynamicAuthorizationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Slf4j
@Component("authorizationManager")
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final DynamicAuthorizationService dynamicAuthorizationService;
    private final CacheManager cacheManager;

    private List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

    @PostConstruct
    public void setMapping() {
        log.info("Initializing dynamic URL-Role mappings...");
        // DynamicAuthorizationService의 getUrlRoleMappings()는 @Cacheable이 적용될 것입니다.
        Map<String, String> urlRoleMappings = dynamicAuthorizationService.getUrlRoleMappings();

        this.mappings = urlRoleMappings.entrySet().stream()
                .map(entry -> {
                    String urlPattern = entry.getKey();
                    String accessExpression = entry.getValue(); // "ROLE_ADMIN" 또는 "ROLE_USER or ROLE_MANAGER" 등
                    RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(urlPattern);

                    AuthorizationManager<RequestAuthorizationContext> manager = new WebExpressionAuthorizationManager(accessExpression);
                    return new RequestMatcherEntry<>(requestMatcher, manager);
                })
                .collect(Collectors.toList());
        log.info("Loaded {} dynamic URL-Role mappings.", mappings.size());
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext request) {
        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {
            RequestMatcher matcher = mapping.getRequestMatcher();
            RequestMatcher.MatchResult matchResult = matcher.matcher(request.getRequest());

            if (matchResult.isMatch()) {
                AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
                log.debug("Matching URL: {} with access expression: '{}'",
                        request.getRequest().getRequestURI(), manager.toString()); // WebExpressionAuthorizationManager는 표현식 문자열을 반환
                return manager.check(authentication,
                        new RequestAuthorizationContext(request.getRequest(), matchResult.getVariables()));
            }
        }
        log.debug("No matching URL pattern found for {}. Defaulting to deny.", request.getRequest().getRequestURI());
        return new AuthorizationDecision(false); // 매핑된 URL이 없으면 기본적으로 거부
    }

    @Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {}

    /**
     * 동적 권한 매핑을 갱신합니다.
     * 권한 정보가 DB 에서 변경될 때 이 메서드를 호출하여 최신 정보를 로드합니다.
     */
    public synchronized void reload() {
        log.info("Reloading dynamic URL-Role mappings...");
        // PersistentUrlRoleMapper의 캐시를 명시적으로 무효화하여 최신 데이터를 가져오도록 합니다.
        // usersWithAuthorities` 캐시도 함께 무효화하여 사용자 권한 정보도 최신으로 유지합니다.
        Optional.ofNullable(cacheManager.getCache("resourcesUrlRoleMappings")).ifPresent(Cache::clear);
        Optional.ofNullable(cacheManager.getCache("resources")).ifPresent(Cache::clear);
        Optional.ofNullable(cacheManager.getCache("usersWithAuthorities")).ifPresent(Cache::clear);

        // 이제 setMapping()을 다시 호출하여 새로운 매핑을 로드합니다.
        setMapping();
        log.info("Dynamic URL-Role mappings reloaded successfully.");
    }
}
