package io.springsecurity.springsecurity6x.security.permission;

import io.springsecurity.springsecurity6x.admin.repository.PermissionRepository;
import io.springsecurity.springsecurity6x.admin.service.DocumentService;
import io.springsecurity.springsecurity6x.entity.Document;
import io.springsecurity.springsecurity6x.security.core.auth.PermissionAuthority;
import io.springsecurity.springsecurity6x.security.service.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component("customPermissionEvaluator")
@RequiredArgsConstructor
@Slf4j
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final PermissionRepository permissionRepository;
    private final DocumentService documentService;

    /**
     * hasPermission(targetDomainObject, permission)
     * 예: @PreAuthorize("#dynamicAccessRule.getValue(#root)") 안에서 호출되는 hasPermission(#document, 'READ')
     * Authentication이 가진 PermissionAuthority를 활용하여 권한을 평가합니다.
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            log.debug("Permission evaluation denied: Authentication null/unauthenticated or permission not String.");
            return false;
        }

        String requiredPermissionAction = ((String) permission).toUpperCase(); // 요구되는 행동 타입 (예: "READ", "WRITE")
        String targetType = (targetDomainObject != null) ? targetDomainObject.getClass().getSimpleName().toUpperCase() : null; // 대상 객체 타입

        // 1. Authentication이 가진 GrantedAuthority 목록에서 해당 PermissionAuthority가 있는지 확인
        boolean hasRequiredPermission = authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof PermissionAuthority)
                .map(auth -> (PermissionAuthority) auth)
                .anyMatch(pa -> pa.getActionType().equalsIgnoreCase(requiredPermissionAction) &&
                        (targetType == null || pa.getTargetType().equalsIgnoreCase(targetType)));

        if (hasRequiredPermission) {
            log.debug("User {} has direct PermissionAuthority for action '{}' on target type '{}'. Proceeding to object-specific check.",
                    authentication.getName(), requiredPermissionAction, targetType);

            // 객체 소유권 확인 로직 (hasPermission(Serializable, String, Object)에서 자세히 처리)
            if ("OWNER_CHECK".equalsIgnoreCase(requiredPermissionAction) && targetDomainObject != null) {
                if (targetDomainObject instanceof Document) {
                    if (authentication.getPrincipal() instanceof CustomUserDetails) {
                        String currentUsername = ((CustomUserDetails) authentication.getPrincipal()).getUsername();
                        Document document = (Document) targetDomainObject;
                        return documentService.isUserOwnerOfDocument(document.getId(), currentUsername);
                    }
                }
            }
            return true;
        }

        log.debug("Permission evaluation denied for user {} for target {} and permission '{}'. No matching PermissionAuthority found.",
                authentication.getName(), targetDomainObject != null ? targetDomainObject.getClass().getSimpleName() : "null", requiredPermissionAction);
        return false;
    }

    /**
     * hasPermission(targetId, targetType, permission)
     * 예: @PreAuthorize("#dynamicAccessRule.getValue(#root)") 안에서 호출되는 hasPermission(#documentId, 'Document', 'WRITE')
     * 이 메서드는 특정 ID와 타입에 대한 권한을 평가할 때 사용됩니다.
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            log.debug("Permission evaluation denied (by ID): Authentication null/unauthenticated or permission not String.");
            return false;
        }

        String requiredAction = ((String) permission).toUpperCase();
        String targetDomainType = targetType.toUpperCase();
        String fullPermissionName = targetDomainType + "_" + requiredAction;

        // 1. 사용자에게 직접 부여된 PermissionAuthority 확인
        boolean hasBasePermission = authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof PermissionAuthority)
                .map(auth -> (PermissionAuthority) auth)
                .anyMatch(pa -> pa.getPermissionName().equalsIgnoreCase(fullPermissionName) &&
                        (pa.getTargetType() == null || pa.getTargetType().equalsIgnoreCase(targetDomainType)));

        if (hasBasePermission) {
            log.debug("User {} has PermissionAuthority '{}' for target ID {} and type '{}'. Proceeding to object-specific check.",
                    authentication.getName(), fullPermissionName, targetId, targetType);

            // 객체 소유권 확인 등 추가적인 DB 조회 기반의 동적 인가 로직 구현
            if (targetDomainType.equalsIgnoreCase("DOCUMENT")) {
                if (authentication.getPrincipal() instanceof CustomUserDetails) {
                    String currentUsername = ((CustomUserDetails) authentication.getPrincipal()).getUsername();
                    return documentService.isUserOwnerOfDocument(targetId, currentUsername);
                }
            }
            // 다른 도메인 객체 타입에 대한 추가 로직 (예: BOARD, FILE 등)

            return true;
        }

        log.debug("Permission evaluation denied for user {} on target ID {} (type '{}') with permission '{}'. No matching PermissionAuthority found.",
                authentication.getName(), targetId, targetType, fullPermissionName);
        return false;
    }
}