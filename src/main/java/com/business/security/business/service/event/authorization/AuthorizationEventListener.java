package com.business.security.business.service.event.authorization;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.stereotype.Component;

/**
 * <b> AuthorizationEventListener </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-14
 */

@ConditionalOnProperty(value = "security.type", havingValue = "event-3", matchIfMissing = false)

@Component
public class AuthorizationEventListener {

    @EventListener
    public void onAuthorization(AuthorizationEvent event){
        System.out.println("event = " + event.getAuthentication().get().getAuthorities());
    }
    @EventListener
    public void onAuthorization(AuthorizationDeniedEvent failure){
        System.out.println("event = " + failure.getAuthentication().get().getAuthorities());
    }

    @EventListener
    public void onAuthorization(AuthorizationGrantedEvent success){
        System.out.println("event = " + success.getAuthentication().get().getAuthorities());
    }
}