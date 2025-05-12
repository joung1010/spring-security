package com.business.security.business.service.authorization.method.annotations;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

/**
 * <b> OwnerShip </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE,ElementType.METHOD})
@PostAuthorize("returnObject.owner == authentication.name")
public @interface OwnerShip {
}
