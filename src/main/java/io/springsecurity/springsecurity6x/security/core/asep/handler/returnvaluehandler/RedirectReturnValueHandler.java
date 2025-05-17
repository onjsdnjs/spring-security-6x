package io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler;

import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.web.util.UriComponentsBuilder; // URL 처리를 위해

import java.io.IOException;

public class RedirectReturnValueHandler implements SecurityHandlerMethodReturnValueHandler {

    private static final Logger logger = LoggerFactory.getLogger(RedirectReturnValueHandler.class);
    private static final String REDIRECT_URL_PREFIX = "redirect:";

    @Override
    public boolean supportsReturnType(MethodParameter returnType) {
        // String 타입을 반환하고, 실제 값이 "redirect:"로 시작하는 경우 이 핸들러가 처리
        return String.class.isAssignableFrom(returnType.getParameterType());
    }

    @Override
    public void handleReturnValue(@Nullable Object returnValue,
                                  MethodParameter returnType,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  HandlerMethod handlerMethod,
                                  @Nullable MediaType resolvedMediaType) throws IOException {

        if (returnValue == null) {
            logger.debug("Redirect target URL is null, nothing to do.");
            return;
        }

        String url = returnValue.toString();
        if (!url.startsWith(REDIRECT_URL_PREFIX)) {
            // 이 핸들러는 "redirect:"로 시작하는 문자열만 처리해야 함.
            // supportsReturnType에서 String만 체크했으므로, 실제 값은 여기서 확인.
            // 만약 다른 String 반환 값 핸들러(예: 뷰 이름 처리)가 있다면, 그 핸들러가 처리하도록 여기서는 아무것도 하지 않거나 예외를 던져야 함.
            // 현재 설계에서는 리다이렉션이 아닌 String은 다른 핸들러가 없으므로, 문제가 될 수 있음.
            // 따라서 supportsReturnType에서 실제 값까지 확인하거나, 이 핸들러의 우선순위를 매우 낮게 설정해야 함.
            // 또는, String을 반환하는 다른 기본 핸들러(예: 뷰 이름 처리)를 추가하고 이 핸들러보다 우선순위를 높게 설정.
            // 여기서는 일단 리다이렉션이 아니면 아무것도 하지 않는 것으로 가정.
            // (실제로는 이 경우, Invoker에서 다음 ReturnValueHandler를 찾도록 해야 함)
            // --> invokeAndHandle 로직에서 supportsReturnType을 먼저 호출하므로,
            //     여기서는 returnValue가 redirect: 로 시작하지 않으면 문제가 될 수 있다.
            //     String을 반환하지만 redirect가 아닌 경우는 다른 ReturnValueHandler가 처리해야 한다.
            //     현재로서는 이 핸들러가 String 타입에 대해 너무 광범위하게 매칭될 수 있으므로,
            //     supportsReturnType을 더 정교하게 만들거나, 다른 String 처리 핸들러를 추가해야 함.
            //     우선은 String 타입이고, redirect: 로 시작할 때만 동작하도록 handleReturnValue 내부에서 한번 더 체크.
            logger.trace("Return value does not start with 'redirect:', RedirectReturnValueHandler will not process it.");
            return; // 다른 String 처리 핸들러에게 기회를 넘겨야 함 (현재 Invoker 구조에서는 다음 핸들러를 찾지 않음 - 개선 필요)
        }

        String redirectUrl = url.substring(REDIRECT_URL_PREFIX.length());

        if (response.isCommitted()) {
            logger.warn("Response already committed. Ignoring redirect to [{}].", redirectUrl);
            return;
        }

        // URL 재작성 (컨텍스트 패스 등 고려) 및 인코딩
        // HttpServletResponse.encodeRedirectURL 사용
        String encodedRedirectUrl = response.encodeRedirectURL(
                UriComponentsBuilder.fromUriString(redirectUrl).build().toUriString()
        );

        if (logger.isDebugEnabled()) {
            logger.debug("Redirecting to [{}]", encodedRedirectUrl);
        }
        response.sendRedirect(encodedRedirectUrl);
    }
}
