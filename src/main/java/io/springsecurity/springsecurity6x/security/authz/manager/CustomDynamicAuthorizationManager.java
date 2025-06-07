package io.springsecurity.springsecurity6x.security.authz.manager;

import io.springsecurity.springsecurity6x.entity.policy.Policy;
import io.springsecurity.springsecurity6x.entity.policy.PolicyTarget;
import io.springsecurity.springsecurity6x.security.authz.resolver.ExpressionAuthorizationManagerResolver;
import io.springsecurity.springsecurity6x.security.authz.service.PolicyRetrievalPoint;
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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

@Slf4j
@Component("customDynamicAuthorizationManager")
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final PolicyRetrievalPoint policyRetrievalPoint; // <<< DynamicAuthorizationService 대신 PRP 주입
    private final ExpressionAuthorizationManagerResolver managerResolver;
    private List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

    @PostConstruct
    public void initialize() {
        log.info("Initializing dynamic authorization mappings from Policy model...");
        // <<< 변경됨: PolicyRetrievalPoint 로부터 Policy를 가져와 매핑 생성 >>>
        List<Policy> urlPolicies = policyRetrievalPoint.findUrlPolicies();

        List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> newMappings = new ArrayList<>();

        for (Policy policy : urlPolicies) {
            // 정책의 모든 규칙과 조건을 하나의 SpEL 표현식으로 결합
            String finalExpression = buildExpressionFromPolicy(policy);

            for (PolicyTarget target : policy.getTargets()) {
                RequestMatcher matcher = PathPatternRequestMatcher.withDefaults().matcher(target.getTargetIdentifier());
                AuthorizationManager<RequestAuthorizationContext> manager = managerResolver.resolve(finalExpression);
                newMappings.add(new RequestMatcherEntry<>(matcher, manager));
                log.debug("Mapping URL '{}' to expression '{}' from Policy '{}'", target.getTargetIdentifier(), finalExpression, policy.getName());
            }
        }
        this.mappings = newMappings;
        log.info("Initialization complete. {} dynamic policy-based mappings have been configured.", mappings.size());
    }

    private String buildExpressionFromPolicy(Policy policy) {
        // 모든 Rule과 Condition을 'and'로 연결하여 하나의 SpEL 표현식으로 만듦
        // DENY 정책은 표현식 전체를 not() 으로 감쌀 수 있음
        StringBuilder expressionBuilder = new StringBuilder();

        policy.getRules().forEach(rule -> {
            rule.getConditions().forEach(condition -> {
                if (expressionBuilder.length() > 0) {
                    expressionBuilder.append(" and ");
                }
                expressionBuilder.append("(").append(condition.getExpression()).append(")");
            });
        });

        String finalExpression = expressionBuilder.toString();
        if (policy.getEffect() == Policy.Effect.DENY) {
            return "!" + finalExpression;
        }
        return finalExpression.isEmpty() ? "permitAll" : finalExpression;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        // 이 부분의 로직은 변경 없음 (Dispatcher 역할은 동일)
        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {
            if (mapping.getRequestMatcher().matcher(context.getRequest()).isMatch()) {
                return mapping.getEntry().check(authentication, context);
            }
        }
        return new AuthorizationDecision(false);
    }

    public synchronized void reload() {
        log.info("Reloading dynamic authorization mappings from Policy model...");
        policyRetrievalPoint.clearUrlPoliciesCache(); // PRP의 캐시를 비웁니다.
        initialize();
    }
}