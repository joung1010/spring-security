package com.business.security.business.endpoint.authorization.model;

import lombok.*;

/**
 * <b> AccountVo </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountVo {
    private String owner;
    private boolean isSecure;
}
