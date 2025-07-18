package com.business.security.business.service.authorization.method;

import com.business.security.business.endpoint.authorization.model.AccountVo;
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

@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization5", matchIfMissing = false)
@Service
public class CustomMethodAuthorizationDataService {

    @PreAuthorize(value = "")
    public String getUser() {
        return "user";
    }

    @PostAuthorize(value = "")
    public AccountVo getOwner(String name) {
        return AccountVo.builder()
                .owner(name)
                .isSecure(false)
                .build();
    }

    public String display() {
        return "display";
    }
}
