package com.business.security.business.service.event.authentication;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;

/**
 * <b> CustomAuthenticationSuccessEvent </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-14
 */
public class CustomAuthenticationSuccessEvent extends AbstractAuthenticationEvent {
    public CustomAuthenticationSuccessEvent(Authentication authentication) {
        super(authentication);
    }
}
