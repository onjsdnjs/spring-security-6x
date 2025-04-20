package io.springsecurity.springsecurity6x.ott;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class MagicLinkHandler implements OneTimeTokenGenerationSuccessHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       OneTimeToken token) throws IOException {
        String link = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath() + "/login/ott")
                .queryParam("token", token.getTokenValue())
                .build(true).toUriString();

        System.out.printf("[DEV‑MAIL] send to %s -> %s%n", token.getUsername(), link);

        response.sendRedirect("/ott/sent");
    }
}
