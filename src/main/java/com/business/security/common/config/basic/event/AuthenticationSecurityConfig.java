package com.business.security.common.config.basic.event;

import com.business.security.business.service.event.authentication.CustomAuthenticationProviderV2;
import com.business.security.business.service.event.authentication.CustomAuthenticationSuccessEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * <b> AuthenticationSecurityConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-14
 */
@ConditionalOnProperty(value = "security.type", havingValue = "event-1", matchIfMissing = false)

@EnableWebSecurity
@RequiredArgsConstructor
@Configuration
public class AuthenticationSecurityConfig {
    private final ApplicationContext applicationContext;
//    private final AuthenticationProvider authenticationProvider;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (webSecurity) -> {
            webSecurity.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("events/user").hasAuthority("ROLE_USER")
                        .requestMatchers("events/db").hasAuthority("ROLE_DB")
                        .requestMatchers("events/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().permitAll())
                  .formLogin(form -> form
                          .successHandler((request, response, authentication) -> {
                              applicationContext.publishEvent(new CustomAuthenticationSuccessEvent(authentication));
                              response.sendRedirect("/");
                          }))
//                .authenticationProvider(authenticationProvider);
                .authenticationProvider(customAuthenticationProvider2())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public AuthenticationProvider customAuthenticationProvider2(){
        return new CustomAuthenticationProviderV2(authenticationEventPublisher(null));
    }

    @Bean
    public DefaultAuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        DefaultAuthenticationEventPublisher authenticationEventPublisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);
        return authenticationEventPublisher;
    }
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails db = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN","SECURE").build();
        return  new InMemoryUserDetailsManager(user, db, admin);
    }
}
