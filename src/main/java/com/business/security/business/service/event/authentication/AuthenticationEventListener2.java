package com.business.security.business.service.event.authentication;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.*;
import org.springframework.stereotype.Component;

/**
 * <b> AuthenticationEventListener2 </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-15
 */

@ConditionalOnProperty(value = "security.type", havingValue = "event-2", matchIfMissing = false)

@Component
public class AuthenticationEventListener2 {
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onSuccess(InteractiveAuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(CustomAuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(AuthenticationFailureProviderNotFoundEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(CustomAuthenticationFailureEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(DefaultAuthenticationFailureEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }
}
