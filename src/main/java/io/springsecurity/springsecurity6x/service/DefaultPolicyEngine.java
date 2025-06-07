package io.springsecurity.springsecurity6x.service;

import io.springsecurity.springsecurity6x.entity.policy.*;
import io.springsecurity.springsecurity6x.repository.PolicyRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.ParameterRequestMatcher;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Slf4j
@RequiredArgsConstructor
public class DefaultPolicyEngine implements PolicyEngine {

    private final PolicyRepository policyRepository;
    private final RiskEngine riskEngine;
    private final SpelExpressionParser expressionParser = new SpelExpressionParser();

    // 단순 권한 체크를 위한 정규식 패턴 (최적화) >>>
    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("^hasAuthority\\('(.+?)'\\)$");
    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile("^hasRole\\('(.+?)'\\)$");


    @Override
    public boolean evaluate(Authentication authentication, HttpServletRequest request, Object targetObject) {
        List<Policy> applicablePolicies = policyRepository.findByTargetTypeWithDetails("URL");

        for (Policy policy : applicablePolicies) {
            for (PolicyTarget target : policy.getTargets()) {
                PathPatternRequestMatcher matcher = PathPatternRequestMatcher.withDefaults().matcher(target.getTargetIdentifier());
                if (matcher.matches(request)) {
                    // 정책 규칙 평가
                    boolean allRulesPassed = areAllRulesSatisfied(policy, authentication, request, targetObject);
                    if (allRulesPassed) {
                        log.info("Policy '{}' matched for URI '{}'. Decision: {}", policy.getName(), request.getRequestURI(), policy.getEffect());
                        return policy.getEffect() == Policy.Effect.ALLOW;
                    }
                }
            }
        }
        log.debug("No applicable policy found for request: {}. Denying access by default.", request.getRequestURI());
        return false;
    }

    private boolean areAllRulesSatisfied(Policy policy, Authentication authentication, HttpServletRequest request, Object targetObject) {
        if (policy.getRules().isEmpty()) {
            return true; // 규칙이 없는 정책은 항상 참
        }

        int riskScore = riskEngine.calculateRiskScore(authentication, request);
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("auth", authentication);
        context.setVariable("user", authentication.getPrincipal());
        context.setVariable("request", request);
        context.setVariable("riskScore", riskScore);
        context.setVariable("target", targetObject);

        for (PolicyRule rule : policy.getRules()) {
            if (!isRuleSatisfied(rule, context)) {
                return false; // 하나의 규칙이라도 실패하면 전체 실패
            }
        }
        return true;
    }

    private boolean isRuleSatisfied(PolicyRule rule, StandardEvaluationContext context) {
        if (rule.getConditions().isEmpty()) {
            return true; // 조건이 없는 규칙은 항상 참
        }
        for (PolicyCondition condition : rule.getConditions()) {
            if (!evaluateCondition(condition.getExpression(), context)) {
                return false; // 하나의 조건이라도 실패하면 규칙 실패
            }
        }
        return true;
    }

    private boolean evaluateCondition(String expression, StandardEvaluationContext context) {
        // 단순 권한 체크 최적화
        Matcher hasAuthorityMatcher = HAS_AUTHORITY_PATTERN.matcher(expression);
        if (hasAuthorityMatcher.matches()) {
            String authority = hasAuthorityMatcher.group(1);
            return checkAuthority((Authentication) context.lookupVariable("auth"), authority);
        }

        Matcher hasRoleMatcher = HAS_ROLE_PATTERN.matcher(expression);
        if (hasRoleMatcher.matches()) {
            String role = "ROLE_" + hasRoleMatcher.group(1);
            return checkAuthority((Authentication) context.lookupVariable("auth"), role);
        }

        // 복잡한 표현식은 SpEL로 평가 >>>
        try {
            Boolean result = expressionParser.parseExpression(expression).getValue(context, Boolean.class);
            return Boolean.TRUE.equals(result);
        } catch (Exception e) {
            log.error("Error evaluating SpEL condition: [{}]", expression, e);
            return false;
        }
    }

    private boolean checkAuthority(Authentication authentication, String authority) {
        if (authentication == null || authentication.getAuthorities() == null) {
            return false;
        }
        boolean granted = authentication.getAuthorities().stream()
                .anyMatch(ga -> ga.getAuthority().equals(authority));
        log.trace("Optimized check for authority '{}': {}", authority, granted);
        return granted;
    }
}