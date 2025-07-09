package com.business.security.business.service.authorization.method;

import com.business.security.business.service.authorization.method.model.vo.Account4Vo;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * <b> MethodAuthorizationDataService </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-09
 */

@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization4", matchIfMissing = false)
@Service
public class MethodAuthorizationDataService {

    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    public String getUser() {
        return "user";
    }

    @PostAuthorize("returnObject.owner == authentication.name")
    public Account4Vo getOwner(String name) {
        return Account4Vo.builder()
                .owner(name)
                .isSecure(false)
                .build();
    }

    public String display() {
        return "display";
    }
}
