package io.springsecurity.springsecurity6x.security.authz.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface RiskEngine {
    int calculateRiskScore(Authentication authentication, HttpServletRequest request);
}
