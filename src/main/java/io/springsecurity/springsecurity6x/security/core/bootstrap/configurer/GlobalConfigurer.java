package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.filter.ASEPFilter;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextHolderFilter;

/**
 * 글로벌 HTTP 보안 설정을 적용합니다.
 */
@Slf4j
public class GlobalConfigurer implements SecurityConfigurer {
    private final ASEPFilter asepFilter;

    public GlobalConfigurer(ASEPFilter asepFilter) {
        this.asepFilter = asepFilter;
    }

    @Override
    public void init(PlatformContext platformCtx, PlatformConfig config) {}

    @Override
    public void configure(FlowContext ctx) {
        HttpSecurity http = ctx.http();
        AuthenticationFlowConfig flow = ctx.flow();

        log.debug("Configuring flow: {} - Adding ASEPFilter", flow.getTypeName());
        try {
            http.addFilterAfter(this.asepFilter, SecurityContextHolderFilter.class);

            log.info("ASEPFilter added to HttpSecurity for flow: {}", flow.getTypeName());

        } catch (Exception e) {
            log.error("Failed to add ASEPFilter for flow: {}", flow.getTypeName(), e);
        }
        SafeHttpCustomizer<HttpSecurity> customizer = ctx.config().getGlobalCustomizer();

        if (customizer != null) {
            try {
                customizer.customize(http); // 이미 ASEPFilter가 추가된 http 객체에 customizer 적용
            } catch (Exception ex) {
                log.warn("Global customizer failed for flow: {}", flow.getTypeName(), ex);
            }
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }
}

