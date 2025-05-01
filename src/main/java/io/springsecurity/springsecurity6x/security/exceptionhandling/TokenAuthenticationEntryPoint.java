package io.springsecurity.springsecurity6x.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.ErrorResponse;
import io.springsecurity.springsecurity6x.security.enums.ErrorCode;
import io.springsecurity.springsecurity6x.security.utils.WebUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.Instant;

public class TokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper mapper = new ObjectMapper(); // or @Autowired 가능

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {

        if (WebUtil.isApiOrAjaxRequest(request)) {
            response.setContentType("application/json; charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            ErrorResponse body = new ErrorResponse(
                    Instant.now().toString(),
                    HttpServletResponse.SC_UNAUTHORIZED,
                    ErrorCode.AUTH_FAILED.code(),
                    ErrorCode.AUTH_FAILED.message(),
                    request.getRequestURI()
            );

            mapper.writeValue(response.getOutputStream(), body);

        } else {
            response.sendRedirect("/loginForm");
        }
    }
}
