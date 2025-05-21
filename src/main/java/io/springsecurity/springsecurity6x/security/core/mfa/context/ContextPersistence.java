package io.springsecurity.springsecurity6x.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;

public interface ContextPersistence {

    @Nullable
        // FactorContext가 없을 수 있음을 명시
    FactorContext contextLoad(HttpServletRequest req);

    // FactorContext 저장 시 HttpServletRequest도 받도록 변경 (세션 접근 위해)
    void saveContext(@Nullable FactorContext ctx, HttpServletRequest req);

    // FactorContext 대신 HttpServletRequest를 받아 해당 요청의 컨텍스트를 삭제하도록 변경
    void deleteContext(HttpServletRequest req);
}