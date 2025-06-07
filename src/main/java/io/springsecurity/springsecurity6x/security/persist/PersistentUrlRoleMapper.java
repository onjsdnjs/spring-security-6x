package io.springsecurity.springsecurity6x.security.persist;

import io.springsecurity.springsecurity6x.admin.repository.ResourcesRepository;
import io.springsecurity.springsecurity6x.entity.Resources;
import io.springsecurity.springsecurity6x.entity.ResourcesRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class PersistentUrlRoleMapper implements UrlRoleMapper { // UrlRoleMapper 인터페이스는 귀하의 프로젝트에 정의되어 있어야 함 (기존에 제공됨)

    private final ResourcesRepository resourcesRepository;

    // 매핑은 캐시되지 않고, getUrlRoleMappings 호출 시마다 최신 데이터를 로드합니다.
    // 하지만 이 메서드를 호출하는 CustomDynamicAuthorizationManager에서 캐싱을 적용할 수 있습니다.
    // 또는, 이 메서드 자체에 캐싱을 적용할 수 있습니다.
    @Override
    @Cacheable(value = "resourcesUrlRoleMappings", key = "'all'") // URL-Role 매핑 전체 캐싱
    public Map<String, String> getUrlRoleMappings() {
        log.debug("Loading URL-Role mappings from database...");
        List<Resources> resourcesList = resourcesRepository.findAllResources(); // 이미 Role 정보까지 fetch join
        LinkedHashMap<String, String> urlRoleMappings = new LinkedHashMap<>();

        // Resources 엔티티의 resourcesRoles (OneToMany to ResourcesRole) 필드 사용
        resourcesList.forEach(resource -> {
            Optional.ofNullable(resource.getResourcesRoles())
                    .orElse(new HashSet<>()) // null 방지
                    .stream()
                    .map(ResourcesRole::getRole) // ResourcesRole에서 Role 엔티티 추출
                    .filter(java.util.Objects::nonNull) // null인 Role 필터링
                    .forEach(role -> {
                        // URL 패턴과 역할 이름을 매핑.
                        // 한 URL에 여러 역할이 매핑될 수 있으므로, Spring Security의 접근 표현식에 맞춰 결합해야 함.
                        // 예: "hasAnyRole('ROLE_ADMIN', 'ROLE_USER')"
                        // 여기서는 일단 단일 역할로 처리하거나, 쉼표로 구분하여 표현식으로 전달합니다.
                        // CustomDynamicAuthorizationManager 에서 WebExpressionAuthorizationManager를 사용할 때,
                        // 이 문자열을 SpEL 표현식으로 파싱할 수 있어야 합니다.
                        // 'role.getRoleName()'은 "ADMIN" 형태이므로 "ROLE_ADMIN"으로 변환하여 사용해야 합니다.
                        String roleName = "ROLE_" + role.getRoleName().toUpperCase();
                        if (urlRoleMappings.containsKey(resource.getResourceName())) {
                            // 이미 매핑된 역할이 있다면, OR 연산으로 추가 (예: hasRole('A') or hasRole('B'))
                            String existingExpression = urlRoleMappings.get(resource.getResourceName());
                            urlRoleMappings.put(resource.getResourceName(), existingExpression + " or " + roleName);
                        } else {
                            urlRoleMappings.put(resource.getResourceName(), roleName);
                        }
                    });
        });
        log.debug("Loaded {} URL-Role mappings.", urlRoleMappings.size());
        return urlRoleMappings;
    }
}