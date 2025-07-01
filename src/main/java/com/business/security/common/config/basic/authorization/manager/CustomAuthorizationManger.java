package com.business.security.common.config.basic.authorization.manager;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

/**
 * <b> CustomAuthorizationManger </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-01
 */
public class CustomAuthorizationManger implements AuthorizationManager<RequestAuthorizationContext> {

    private static final String REQUIRED_ROLE = "ROLE_SECURE";

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {

        Authentication auth = authentication.get();
        if (auth == null || !auth.isAuthenticated()) {
            return new AuthorizationDecision(false);
        }

        boolean isRequiredRole = auth.getAuthorities()
                .stream()
                .anyMatch(authority -> REQUIRED_ROLE.equals(authority.getAuthority()));

        return new AuthorizationDecision(isRequiredRole);
    }
}
