package io.springsecurity.springsecurity6x.security.handler.logout;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.util.Map;

public class StrategyAwareLogoutSuccessHandler implements LogoutSuccessHandler {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        mapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다"));
    }
}
