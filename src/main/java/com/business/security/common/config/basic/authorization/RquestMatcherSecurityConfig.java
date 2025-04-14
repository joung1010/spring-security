package com.business.security.common.config.basic.authorization;

import com.business.security.common.config.basic.authorization.matcher.CustomRequestMatcher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
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

/**
 * <b> CorsSecurityConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-03-24
 */

@Slf4j
@EnableWebSecurity
@ConditionalOnProperty(value = "security.type", havingValue = "request-matcher", matchIfMissing = false)

@Configuration
public class RquestMatcherSecurityConfig {


    @Bean
//    @Order(1) /*해당 빈의 우선순위를 더 높게 설정하게 되면 밑에 있는 설정은 작동하지 않는다. 좁은 범위의 설정은 항상 더 큰 범위보다 먼저 동작해야한다.*/
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {

        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }


    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain2(HttpSecurity http, ApplicationContext context) throws Exception {

        http.securityMatchers((matchers) -> matchers.requestMatchers("/api/**","/oauth/**"))
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll());
        return http.build();
    }


    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails manager = User.withUsername("manager").password("{noop}1111").roles("MANAGER").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN").build();
        return new InMemoryUserDetailsManager(user, manager, admin);
    }

}
