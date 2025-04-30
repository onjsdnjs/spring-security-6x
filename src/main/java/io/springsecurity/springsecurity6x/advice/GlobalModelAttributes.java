package io.springsecurity.springsecurity6x.advice;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
@RequiredArgsConstructor
public class GlobalModelAttributes {

    private final AuthContextProperties authContextProperties;

    @ModelAttribute("authMode")
    public String authMode() {
        return authContextProperties.getTokenTransportType().name().toLowerCase(); // "cookie", "header", "header_cookie"
    }
}
