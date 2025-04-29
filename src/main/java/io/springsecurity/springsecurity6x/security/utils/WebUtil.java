package io.springsecurity.springsecurity6x.security.utils;

import jakarta.servlet.http.HttpServletRequest;

public class WebUtil {

    public static boolean isApiOrAjaxRequest(HttpServletRequest request) {
        String accept     = request.getHeader("Accept");
        String xRequested = request.getHeader("X-Requested-With");
        String uri        = request.getRequestURI();

        return (accept != null && accept.contains("application/json"))
                || "XMLHttpRequest".equalsIgnoreCase(xRequested)
                || uri.startsWith("/api/");
    }
}
