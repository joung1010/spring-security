package com.business.security.common.config.basic.authorization.method;

import com.business.security.common.config.basic.authorization.interceptor.CustomMethodInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * <b> MethodInterceptorConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-10
 */

@Slf4j
@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization7", matchIfMissing = false)

@EnableMethodSecurity(prePostEnabled = false)
@Configuration
public class MethodInterceptorConfig {

    @Bean
    public MethodInterceptor interceptor() {
        AuthorizationManager<MethodInvocation> authorizationManager = new AuthenticatedAuthorizationManager<>();
        return new CustomMethodInterceptor(authorizationManager);
    }

    @Bean
    public Pointcut pointcut() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* com.business.security.business.service.authorization.method.CustomPointCutDataService.*(..))");

        return pointcut;
    }

    @Bean
    public Advisor advisor() {
        return new DefaultPointcutAdvisor(pointcut(), interceptor());
    }



}
