package com.business.security.business.service.authorization.method;

import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.stereotype.Component;

/**
 * <b> CustomAuthorization </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Component("myAuthorization")
public class CustomAuthorization {

    public boolean isUser(MethodSecurityExpressionOperations root) {
        boolean decision = root.hasAuthority("ROLE_USER");
        return decision;
    }
}
