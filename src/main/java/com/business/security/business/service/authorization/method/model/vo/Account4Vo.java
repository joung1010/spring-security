package com.business.security.business.service.authorization.method.model.vo;

import lombok.Builder;
import lombok.Getter;

/**
 * <b> AccountVo </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-09
 */

@Getter
@Builder
public class Account4Vo {
    private String owner;
    private boolean isSecure;
}
