package com.business.security.business.endpoint.authorization.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * <b> AccountVo </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AccountVo {
    private String owner;
    private boolean isSecure;
}
