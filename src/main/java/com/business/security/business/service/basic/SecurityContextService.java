package com.business.security.business.service.basic;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * <b> SecurityContextService </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-09-10
 */
@Service
public class SecurityContextService {
    public void securityContext() {
        SecurityContext context = SecurityContextHolder.getContextHolderStrategy().getContext();
        Authentication authentication = context.getAuthentication();
        System.out.println("authentication = " + authentication);
    }
}
