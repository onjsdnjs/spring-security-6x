package io.springsecurity.springsecurity6x.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

// 컨텍스트 저장소: HttpSession 기반 예시
public interface FactorContextManager {
    FactorContext load(HttpServletRequest req);
    void save(FactorContext ctx, HttpServletRequest req);
    void clear(HttpServletRequest req);
}

