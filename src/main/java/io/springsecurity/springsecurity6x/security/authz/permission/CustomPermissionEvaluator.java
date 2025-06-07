package io.springsecurity.springsecurity6x.security.authz.permission;

import io.springsecurity.springsecurity6x.admin.repository.PermissionRepository;
import io.springsecurity.springsecurity6x.admin.service.DocumentService;
import io.springsecurity.springsecurity6x.entity.Permission;
import io.springsecurity.springsecurity6x.security.core.auth.PermissionAuthority;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.util.Optional;

@Component("customPermissionEvaluator")
@RequiredArgsConstructor
@Slf4j
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final PermissionRepository permissionRepository;
    private final DocumentService documentService;
    private final SpelExpressionParser expressionParser = new SpelExpressionParser();

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            log.debug("Permission evaluation denied: Authentication null/unauthenticated or permission not String.");
            return false;
        }

        String requiredPermissionAction = ((String) permission).toUpperCase();
        String targetType = (targetDomainObject != null) ? targetDomainObject.getClass().getSimpleName().toUpperCase() : null;

        return authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof PermissionAuthority)
                .map(auth -> (PermissionAuthority) auth)
                .filter(pa -> pa.getActionType().equalsIgnoreCase(requiredPermissionAction) &&
                        (targetType == null || pa.getTargetType().equalsIgnoreCase(targetType)))
                .anyMatch(pa -> {
                    // <<< 변경됨: 권한 확인 후 조건 표현식 평가 로직 추가
                    log.debug("User {} has base permission '{}'. Evaluating condition...", authentication.getName(), pa.getPermissionName());
                    return evaluateCondition(pa.getPermissionName(), authentication, targetDomainObject);
                });
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            log.debug("Permission evaluation denied (by ID): Authentication null/unauthenticated or permission not String.");
            return false;
        }

        String requiredAction = ((String) permission).toUpperCase();
        String targetDomainType = targetType.toUpperCase();
        String fullPermissionName = targetDomainType + "_" + requiredAction;

        return authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof PermissionAuthority)
                .map(auth -> (PermissionAuthority) auth)
                .filter(pa -> pa.getPermissionName().equalsIgnoreCase(fullPermissionName))
                .anyMatch(pa -> {
                    // <<< 변경됨: 권한 확인 후 조건 표현식 평가 로직 추가
                    // 여기서는 targetDomainObject가 없으므로, SpEL 표현식 내에서 #targetId와 #targetType을 사용할 수 있도록 해야 함.
                    log.debug("User {} has base permission '{}' for targetId {}. Evaluating condition...",
                            authentication.getName(), fullPermissionName, targetId);
                    return evaluateCondition(pa.getPermissionName(), authentication, targetId);
                });
    }

    /**
     * <<< 추가됨: SpEL 조건 표현식을 평가하는 메서드 >>>
     * @param permissionName DB에서 Permission 엔티티를 찾기 위한 권한 이름
     * @param authentication 현재 인증 객체
     * @param targetObject 권한 평가 대상 객체 (or targetId)
     * @return 조건이 없거나, 평가 결과가 true이면 true 반환
     */
    private boolean evaluateCondition(String permissionName, Authentication authentication, Object targetObject) {
        Optional<Permission> permissionOpt = permissionRepository.findByName(permissionName);
        if (permissionOpt.isEmpty()) {
            log.warn("Permission '{}' not found in database for condition evaluation.", permissionName);
            return false; // DB에 권한이 없으면 거부
        }

        String condition = permissionOpt.get().getConditionExpression();
        if (!StringUtils.hasText(condition)) {
            return true; // 조건이 없으면 항상 통과
        }

        try {
            EvaluationContext context = new StandardEvaluationContext();
            context.setVariable("auth", authentication); // #auth로 Authentication 객체 접근
            context.setVariable("user", authentication.getPrincipal()); // #user로 Principal 객체 접근
            context.setVariable("target", targetObject); // #target으로 대상 객체 또는 ID 접근

            Expression expression = expressionParser.parseExpression(condition);
            Boolean result = expression.getValue(context, Boolean.class);
            log.debug("Evaluated condition '{}' for permission '{}': Result is {}", condition, permissionName, result);
            return Boolean.TRUE.equals(result);
        } catch (Exception e) {
            log.error("Error evaluating SpEL condition '{}' for permission '{}'", condition, permissionName, e);
            return false; // 평가 중 오류 발생 시 안전하게 거부
        }
    }
}