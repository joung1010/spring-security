package com.business.security.common.config.basic.integration.annotation;

import org.springframework.security.core.annotation.AuthenticationPrincipal;

import java.lang.annotation.*;

/**
 * <b> CurrentUser </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-21
 */

@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal(expression = "#this == 'anonymousUser' ? null : #this.username")
public @interface CurrentUser {
}
