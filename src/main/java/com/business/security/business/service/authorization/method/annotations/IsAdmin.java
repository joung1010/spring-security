package com.business.security.business.service.authorization.method.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

/**
 * <b> IsAdmin </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE,ElementType.METHOD})
@PreAuthorize("hasRole('ADMIN')")
public @interface IsAdmin {
}
