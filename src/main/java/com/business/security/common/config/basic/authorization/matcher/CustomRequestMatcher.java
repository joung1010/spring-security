package com.business.security.common.config.basic.authorization.matcher;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * <b> CustomRequestMatcher </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-07
 */


public class CustomRequestMatcher implements RequestMatcher {
    private final String urlPatterns;

    public CustomRequestMatcher(String urlPatterns) {
        this.urlPatterns = urlPatterns;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.startsWith(urlPatterns);
    }
}
