package io.springsecurity.springsecurity6x.security.filter.matcher;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.ParameterRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
@Getter
public class MfaUrlMatcher {

    private final String mfaInitiateUrl;
    private final String selectFactorUrl;
    private final String ottRequestCodeUiUrl;
    private final String ottChallengeUrl;
    private final String passkeyChallengeUrl;
    private final String tokenGeneratorUrl;
    private final String loginProcessingUrl;

    private final Map<MfaRequestType, RequestMatcher> matchers = new HashMap<>();

    public MfaUrlMatcher(AuthContextProperties authContextProperties, ApplicationContext applicationContext) {
        // URL 설정 초기화
        this.mfaInitiateUrl = authContextProperties.getMfa().getInitiateUrl();
        this.selectFactorUrl = authContextProperties.getMfa().getSelectFactorUrl();
        this.ottRequestCodeUiUrl = authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
        this.ottChallengeUrl = authContextProperties.getMfa().getOttFactor().getChallengeUrl();
        this.passkeyChallengeUrl = authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
        this.tokenGeneratorUrl = authContextProperties.getMfa().getOttFactor().getCodeGenerationUrl();
        this.loginProcessingUrl = authContextProperties.getMfa().getOttFactor().getLoginProcessingUrl();

        // 매처 초기화
        initializeMatchers();
    }

    private void initializeMatchers() {
        matchers.put(MfaRequestType.MFA_INITIATE,
                new ParameterRequestMatcher(mfaInitiateUrl, HttpMethod.GET.name()));
        matchers.put(MfaRequestType.SELECT_FACTOR,
                new ParameterRequestMatcher(selectFactorUrl, HttpMethod.GET.name()));
        matchers.put(MfaRequestType.OTT_REQUEST_UI,
                new ParameterRequestMatcher(ottRequestCodeUiUrl, HttpMethod.GET.name()));
        matchers.put(MfaRequestType.OTT_CHALLENGE,
                new ParameterRequestMatcher(ottChallengeUrl, HttpMethod.GET.name()));
        matchers.put(MfaRequestType.PASSKEY_CHALLENGE,
                new ParameterRequestMatcher(passkeyChallengeUrl, HttpMethod.GET.name()));
        matchers.put(MfaRequestType.TOKEN_GENERATION,
                new ParameterRequestMatcher(tokenGeneratorUrl, HttpMethod.POST.name()));
        matchers.put(MfaRequestType.LOGIN_PROCESSING,
                new ParameterRequestMatcher(loginProcessingUrl, HttpMethod.POST.name()));
    }

    public RequestMatcher createRequestMatcher() {
        return new OrRequestMatcher(new ArrayList<>(matchers.values()));
    }

    public MfaRequestType getRequestType(HttpServletRequest request) {
        for (Map.Entry<MfaRequestType, RequestMatcher> entry : matchers.entrySet()) {
            if (entry.getValue().matches(request)) {
                return entry.getKey();
            }
        }
        return MfaRequestType.UNKNOWN;
    }

    public Set<String> getConfiguredUrls() {
        return Set.of(mfaInitiateUrl, selectFactorUrl, ottRequestCodeUiUrl,
                ottChallengeUrl, passkeyChallengeUrl, tokenGeneratorUrl, loginProcessingUrl);
    }
}

enum MfaRequestType {
    MFA_INITIATE,
    SELECT_FACTOR,
    OTT_REQUEST_UI,
    OTT_CHALLENGE,
    PASSKEY_CHALLENGE,
    TOKEN_GENERATION,
    LOGIN_PROCESSING,
    UNKNOWN
}
