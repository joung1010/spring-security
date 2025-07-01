package com.business.security.common.config.basic.authorization.manager;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import java.util.List;
import java.util.function.Supplier;

/**
 * <b> CustomRequestMatcherDelegatingAuthorizationManager </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-01
 */
public class CustomRequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final RequestMatcherDelegatingAuthorizationManager manager;


    public CustomRequestMatcherDelegatingAuthorizationManager(final List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings) {
        this.manager = RequestMatcherDelegatingAuthorizationManager.builder().mappings(map -> map.addAll(mappings)).build();
    }

    @Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        AuthorizationManager.super.verify(authentication, object);
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        return manager.check(authentication, object.getRequest());
    }
}
