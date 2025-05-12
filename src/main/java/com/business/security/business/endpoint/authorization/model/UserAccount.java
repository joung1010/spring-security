package com.business.security.business.endpoint.authorization.model;

import lombok.Builder;
import lombok.Getter;

/**
 * <b> UserAccount </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-21
 */

@Getter
@Builder
public class UserAccount {
    private String owner;
    private boolean isSecure;
}
