package io.springsecurity.springsecurity6x.security.authz.pip;
import io.springsecurity.springsecurity6x.security.authz.context.AuthorizationContext;

import java.util.Map;

/**
 * PIP (Policy Information Point): 정책 정보 지점.
 * PDP가 정책 평가에 필요한 속성 정보를 조회하는 책임.
 */
public interface AttributeInformationPoint {
    /**
     * 주어진 컨텍스트를 기반으로 필요한 추가 속성을 조회하여 반환합니다.
     * @param context 현재 인가 컨텍스트
     * @return 추가 속성 Map
     */
    Map<String, Object> getAttributes(AuthorizationContext context);
}
