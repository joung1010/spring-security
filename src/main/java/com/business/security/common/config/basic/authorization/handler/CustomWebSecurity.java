package com.business.security.common.config.basic.authorization.handler;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * <b> CustomWebSecurity </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-07
 */

@Slf4j
@ConditionalOnProperty(value = "security.type", havingValue = "authorization-custom", matchIfMissing = false)

@Component(CustomWebSecurity.BEAN_NAME)
public class CustomWebSecurity {
    public static final String BEAN_NAME = "customWebSecurity";

    public boolean check(Authentication authentication, HttpServletRequest request) {
        return authentication.isAuthenticated();
    }
}
