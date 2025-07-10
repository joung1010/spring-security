package com.business.security.common.config.basic.authorization.interceptor;

import lombok.RequiredArgsConstructor;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.file.AccessDeniedException;

/**
 * <b> CustomMethodInterceptor </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-10
 */

@RequiredArgsConstructor
public class CustomMethodInterceptor implements MethodInterceptor {

    private final AuthorizationManager authorizationManager;

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        if (authorizationManager.check(() -> authentication, invocation).isGranted()) {
            return invocation.proceed();
        }

        throw new AccessDeniedException("Access denied");
    }
}
