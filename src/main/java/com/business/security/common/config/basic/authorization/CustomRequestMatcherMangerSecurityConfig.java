package com.business.security.common.config.basic.authorization;

import com.business.security.common.config.basic.authorization.manager.CustomAuthorizationManger;
import com.business.security.common.config.basic.authorization.manager.CustomRequestMatcherDelegatingAuthorizationManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.ArrayList;
import java.util.List;

/**
 * <b> CustomRequestMatcherMangerSecurityConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-01
 */

@Slf4j
@EnableWebSecurity
@ConditionalOnProperty(value = "security.type", havingValue = "authorization-advanced1", matchIfMissing = false)

@Configuration
public class CustomRequestMatcherMangerSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {


        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().access(authorizationManager(introspector)))
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public AuthorizationManager<RequestAuthorizationContext> authorizationManager(HandlerMappingIntrospector introspector) {
        List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings
                = new ArrayList<>();

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> requestMatcherEntry1
                = new RequestMatcherEntry(new MvcRequestMatcher(introspector, "advanced/user"), AuthorityAuthorizationManager.hasAnyAuthority("ROLE_USER"));
        mappings.add(requestMatcherEntry1);

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> requestMatcherEntry2
                = new RequestMatcherEntry(new MvcRequestMatcher(introspector, "advanced/db"), AuthorityAuthorizationManager.hasAnyAuthority("ROLE_DB"));
        mappings.add(requestMatcherEntry2);

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> requestMatcherEntry3
                = new RequestMatcherEntry(new MvcRequestMatcher(introspector, "advanced/admin"), AuthorityAuthorizationManager.hasAnyAuthority("ROLE_ADMIN"));
        mappings.add(requestMatcherEntry3);

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> requestMatcherEntry4
                = new RequestMatcherEntry(AnyRequestMatcher.INSTANCE, new AuthenticatedAuthorizationManager<>());
        mappings.add(requestMatcherEntry4);


        return new CustomRequestMatcherDelegatingAuthorizationManager(mappings);
    }


    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails manager = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "SECURE").build();
        return new InMemoryUserDetailsManager(user, manager, admin);
    }
}
