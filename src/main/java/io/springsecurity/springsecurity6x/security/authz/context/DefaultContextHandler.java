package io.springsecurity.springsecurity6x.security.authz.context;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class DefaultContextHandler implements ContextHandler {

    @Override
    public AuthorizationContext create(Authentication authentication, HttpServletRequest request) {
        ResourceDetails resource = new ResourceDetails("URL", request.getRequestURI());
        EnvironmentDetails environment = new EnvironmentDetails(request.getRemoteAddr(), LocalDateTime.now());

        return new AuthorizationContext(authentication, resource, request.getMethod(), environment);
    }
}
