package io.springsecurity.springsecurity6x.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.ErrorResponse;
import io.springsecurity.springsecurity6x.security.utils.WebUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.Instant;

public class TokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {

        if (WebUtil.isApiOrAjaxRequest(request)) {

            ErrorResponse body = new ErrorResponse(
                    Instant.now().toString(),
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Unauthorized",
                    authException.getMessage(),
                    request.getRequestURI()
            );

            mapper.writeValue(response.getOutputStream(), body);

        } else {
            response.sendRedirect("/loginForm");
        }
    }
}
