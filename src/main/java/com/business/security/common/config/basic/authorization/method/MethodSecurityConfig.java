package com.business.security.common.config.basic.authorization.method;

import com.business.security.common.config.basic.authorization.manager.CustomPreAuthorizationManger;
import com.business.security.common.config.basic.authorization.manager.CustomPostAuthorizationManger;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.Advisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * <b> MethodSecurityConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-10
 */

@Slf4j
@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization5", matchIfMissing = false)

@EnableMethodSecurity(prePostEnabled = false)
@Configuration
public class MethodSecurityConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor preAuthorize() {
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(new CustomPreAuthorizationManger());
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor postAuthorize() {
        return AuthorizationManagerAfterMethodInterceptor.postAuthorize(new CustomPostAuthorizationManger());
    }

}
