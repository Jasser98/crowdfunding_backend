package com.rif.authentication.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.rif.authentication.models.Permission.*;
import static com.rif.authentication.models.Role.ADMIN;
import static com.rif.authentication.models.Role.USER;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;
    private final AccessDeniedHandler accessDeniedHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws  Exception {
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/auth/**").permitAll()

                .requestMatchers("api/admin/**").hasRole(ADMIN.name())
                    .requestMatchers(GET,"api/admin/**").hasRole(ADMIN_READ.name())
                    .requestMatchers(POST,"api/admin/**").hasRole(ADMIN_CREATE.name())
                    .requestMatchers(PUT,"api/admin/**").hasRole(ADMIN_UPDATE.name())
                    .requestMatchers(DELETE,"api/admin/**").hasRole(ADMIN_DELETE.name())

                .requestMatchers("api/user/**").hasRole(USER.name())
                    .requestMatchers(GET,"api/user/**").hasRole(USER_READ.name())
                    .requestMatchers(POST,"api/user/**").hasRole(USER_CREATE.name())
                    .requestMatchers(PUT,"api/user/**").hasRole(USER_UPDATE.name())
                    .requestMatchers(DELETE,"api/user/**").hasRole(USER_DELETE.name())

                .requestMatchers("api/users/**").hasAnyRole(USER.name(), ADMIN.name())
                    .requestMatchers(GET,"api/users/**").hasAnyAuthority(USER_READ.name(),ADMIN.name())
                    .requestMatchers(POST,"api/users/**").hasAnyAuthority(USER_CREATE.name(),ADMIN.name())
                    .requestMatchers(PUT,"api/users/**").hasAnyAuthority(USER_UPDATE.name(),ADMIN.name())
                    .requestMatchers(DELETE,"api/users/**").hasAnyAuthority(USER_DELETE.name(),ADMIN.name())

                .anyRequest()
                .authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(customAuthenticationEntryPoint) // Utiliser le point d'entrée personnalisé
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler)  // Configurer le gestionnaire d'accès refusé
                .and()
                .logout()
                .logoutUrl("/api/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler(
                        (request, response, authentication) ->
                                SecurityContextHolder.clearContext())
        ;
        return http.build();
    }
}

