package com.business.security.common.config.basic.authorization.manager;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

import java.util.function.Supplier;

/**
 * <b> CustomPreAuthorizationManger </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-10
 */
public class CustomPreAuthorizationManger implements AuthorizationManager<MethodInvocation> {
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation invocation) {
        return new AuthorizationDecision(authentication.get().isAuthenticated());
    }
}
