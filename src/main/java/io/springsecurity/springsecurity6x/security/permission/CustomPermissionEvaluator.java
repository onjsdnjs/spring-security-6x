package io.springsecurity.springsecurity6x.security.permission;

import io.springsecurity.springsecurity6x.admin.repository.PermissionRepository;
import io.springsecurity.springsecurity6x.admin.service.DocumentService;
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
    private final DocumentService documentService; // DocumentService 주입 (예시: Document 엔티티의 소유자를 확인하기 위함)
    // 다른 도메인 서비스가 필요하다면 여기에 추가 주입

    /**
     * hasPermission(targetDomainObject, permission)
     * 예: @PreAuthorize("hasPermission(#document, 'READ')")
     * Authentication이 가진 RoleAuthority와 PermissionAuthority를 활용하여 권한을 평가합니다.
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            log.debug("Permission evaluation denied: Authentication null/unauthenticated or permission not String.");
            return false;
        }

        String requiredPermissionAction = ((String) permission).toUpperCase(); // 요구되는 행동 타입 (예: "READ", "WRITE")
        String targetType = (targetDomainObject != null) ? targetDomainObject.getClass().getSimpleName().toUpperCase() : null; // 대상 객체 타입

        // 1. GrantedAuthority 목록에서 직접적인 PermissionAuthority를 확인합니다.
        // CustomUserDetails는 이미 RoleAuthority와 PermissionAuthority를 생성하여 authorities에 추가했으므로,
        // 이곳에서 모든 유효한 권한을 확인합니다.
        boolean hasRequiredPermission = authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof PermissionAuthority)
                .map(auth -> (PermissionAuthority) auth)
                .anyMatch(pa -> pa.getActionType().equalsIgnoreCase(requiredPermissionAction) &&
                        (targetType == null || pa.getTargetType().equalsIgnoreCase(targetType)));

        if (hasRequiredPermission) {
            log.debug("User {} has direct PermissionAuthority for action '{}' on target type '{}'. Proceeding to object-specific check.",
                    authentication.getName(), requiredPermissionAction, targetType);

            // TODO: (추가) 여기서 targetDomainObject를 활용한 객체 레벨 보안 로직을 구현합니다.
            //       예: 특정 액션(OWNER_CHECK)에 대해 도메인 객체의 소유자를 확인하는 로직
            if ("OWNER_CHECK".equalsIgnoreCase(requiredPermissionAction) && targetDomainObject != null) {
                if (targetDomainObject instanceof io.springsecurity.springsecurity6x.entity.Document document) { // Document 엔티티가 있다고 가정
                    // 현재 인증된 사용자가 문서의 소유자인지 확인
                    if (authentication.getPrincipal() instanceof CustomUserDetails) {
                        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
                        // document.getOwnerUsername()와 userDetails.getUsername() 비교
                        // 예: if (document.getOwnerUsername().equals(userDetails.getUsername())) return true;
                        log.debug("Owner check not fully implemented. Proceeding based on GrantedAuthority only.");
                        return true; // 임시로 true 반환
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
     * 예: @PreAuthorize("hasPermission(#documentId, 'Document', 'WRITE')")
     * 이 메서드는 특정 ID와 타입에 대한 권한을 평가할 때 사용됩니다.
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            log.debug("Permission evaluation denied (by ID): Authentication null/unauthenticated or permission not String.");
            return false;
        }

        String requiredAction = ((String) permission).toUpperCase(); // 요구되는 행동 타입 (예: "READ", "WRITE")
        String targetDomainType = targetType.toUpperCase(); // 대상 객체 타입 (예: "DOCUMENT")
        String fullPermissionName = targetDomainType + "_" + requiredAction; // 예: "DOCUMENT_WRITE"

        // 1. 사용자에게 직접 부여된 PermissionAuthority 또는 Role을 통해 얻은 PermissionAuthority 확인
        // CustomUserDetails는 이미 모든 Role과 Permission을 GrantedAuthority로 로드했으므로,
        // authorities 컬렉션에서 `PermissionAuthority` 객체를 찾아 해당 권한이 있는지 확인합니다.
        boolean hasBasePermission = authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof PermissionAuthority)
                .map(auth -> (PermissionAuthority) auth)
                .anyMatch(pa -> pa.getPermissionName().equalsIgnoreCase(fullPermissionName) &&
                        (pa.getTargetType() == null || pa.getTargetType().equalsIgnoreCase(targetDomainType))); // 대상 타입도 일치하는지 확인


        if (hasBasePermission) {
            log.debug("User {} has PermissionAuthority '{}' for target ID {} and type '{}'. Proceeding to object-specific check.",
                    authentication.getName(), fullPermissionName, targetId, targetType);

            // **TODO: 객체 소유권 확인 등 추가적인 DB 조회 기반의 동적 인가 로직 구현 (가장 중요한 객체 레벨 보안의 핵심)**
            // 이 부분은 사용자님이 직접 경험하시고 강조하셨던 내용입니다.
            // `targetId`와 `targetType`을 사용하여 실제 DB에서 해당 객체를 조회하고,
            // 현재 인증된 사용자(`authentication.getName()`, `authentication.getPrincipal()`)와의 관계를 확인합니다.

            if (targetDomainType.equalsIgnoreCase("DOCUMENT")) { // 예시: "Document" 타입 객체에 대한 권한 검사
                // DocumentService를 통해 문서 정보를 가져와 소유자를 확인하는 로직
                // documentService는 반드시 ID로 문서를 조회하고, 문서 엔티티는 ownerId/ownerUsername 필드를 가집니다.
                // findByIdWithUser()와 같이 User 정보도 함께 가져와야 할 수 있습니다.
                return documentService.isUserOwnerOfDocument(targetId, authentication.getName());

            } else if (targetDomainType.equalsIgnoreCase("BOARD")) { // 예시: "Board" 타입 객체에 대한 권한 검사
                // BoardService를 통해 게시판 정보를 가져와 특정 사용자만 접근 가능한지 확인
                // return boardService.canUserAccessBoard(targetId, authentication.getName(), requiredAction);
                log.warn("Board type permission check not implemented. Defaulting to true for now.");
                return true; // 구현되지 않았다면 임시로 true
            }

            // 추가적인 동적 인가 로직이 없다면 기본적으로 허용
            return true;
        }

        log.debug("Permission evaluation denied for user {} on target ID {} (type '{}') with permission '{}'. No matching PermissionAuthority found.",
                authentication.getName(), targetId, targetType, fullPermissionName);
        return false;
    }
}