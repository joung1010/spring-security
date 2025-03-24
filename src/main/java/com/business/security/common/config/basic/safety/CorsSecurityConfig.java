package com.business.security.common.config.basic.safety;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * <b> CorsSecurityConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-03-24
 */

@Slf4j
@EnableWebSecurity
@ConditionalOnProperty(value = "security.type", havingValue = "cors", matchIfMissing = false)

@Configuration
public class CorsSecurityConfig {
}
