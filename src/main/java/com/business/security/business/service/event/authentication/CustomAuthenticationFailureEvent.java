package com.business.security.business.service.event.authentication;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * <b> CustomAuthenticationFailureEvent </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-14
 */
public class CustomAuthenticationFailureEvent extends AbstractAuthenticationFailureEvent {
    public CustomAuthenticationFailureEvent(Authentication authentication, AuthenticationException exception) {
        super(authentication, exception);
    }
}
