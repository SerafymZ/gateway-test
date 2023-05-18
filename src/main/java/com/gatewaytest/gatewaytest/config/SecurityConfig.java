package com.gatewaytest.gatewaytest.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SecurityConfig {

    private static final String ADMIN_LOGIN = "admin";
    private static final String ADMIN_PASSWORD = "{noop}admin";
    private static final String USER_LOGIN = "user";
    private static final String USER_PASSWORD = "{noop}user";

    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_USER = "USER";

    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity) {

//        ReactiveAuthenticationManager authenticationManager = authentication -> {
//            authentication.setAuthenticated("admin".equals(authentication.getName()));

//            if (authentication != null &&
//                    authentication.getPrincipal() != null &&
//                    authentication.getCredentials() != null) {
//                boolean isAdmin = ADMIN_LOGIN.equals(authentication.getPrincipal()) &&
//                        ADMIN_PASSWORD.equals(authentication.getCredentials());
//                boolean isUser = USER_LOGIN.equals(authentication.getPrincipal()) &&
//                        USER_PASSWORD.equals(authentication.getCredentials());
//                if (isAdmin || isUser) {
//                    authentication.setAuthenticated(true);
//                }
//            }

//            authentication.setAuthenticated(true);
//            int a = 0;

//            UserDetailsService userDetailsService = userDetailsService();
//            UserDetails adminDetails = userDetailsService.loadUserByUsername(ADMIN_LOGIN);

//            Authentication authentication
//                    = new UsernamePasswordAuthenticationToken("admin", "admin", List.of(ROLE_ADMIN));

//            return Mono.just(authentication);
//        };



//        var userDetailsService = userDetailsService();
//        UserDetails adminDetails = userDetailsService.loadUserByUsername(ADMIN_LOGIN);
//        UserDetails userDetails = userDetailsService.loadUserByUsername(USER_LOGIN);
//        var mapReactiveUserDetailsService = new MapReactiveUserDetailsService(adminDetails, userDetails);
//        ReactiveAuthenticationManager authenticationManager =
//                new UserDetailsRepositoryReactiveAuthenticationManager(mapReactiveUserDetailsService);



//        List<UserDetails> userDetailsList = new ArrayList<>();
//        userDetailsList.add(User.withUsername(ADMIN_LOGIN).password(ADMIN_PASSWORD).roles(ROLE_ADMIN).build());
//        userDetailsList.add(User.withUsername(USER_LOGIN).password(USER_PASSWORD).roles(ROLE_USER).build());
//
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(userDetailsList);

        httpSecurity
                .authorizeExchange((authorize) -> authorize
                        .pathMatchers(HttpMethod.GET, "/api/v1/user").hasAnyRole(ROLE_USER, ROLE_ADMIN)
                        .pathMatchers(HttpMethod.GET, "/api/v1/user/{id:\\d+}").hasAnyRole(ROLE_USER, ROLE_ADMIN)
                        .pathMatchers(HttpMethod.POST, "/api/v1/user").hasRole(ROLE_ADMIN)
                        .pathMatchers(HttpMethod.PUT, "/api/v1/user/{id:\\d+}").hasRole(ROLE_ADMIN)
                        .pathMatchers(HttpMethod.DELETE, "/api/v1/user/{id:\\d+}").hasRole(ROLE_ADMIN)
                        .anyExchange().denyAll()
                )
                .httpBasic(httpBasic -> {
//                    httpBasic.authenticationManager(authenticationManager);
                    httpBasic.authenticationManager(createReactiveAuthenticationManager());
                })
                .csrf().disable();
        return httpSecurity.build();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        List<UserDetails> userDetailsList = new ArrayList<>();
//        userDetailsList.add(createUserDetails(ADMIN_LOGIN, ADMIN_PASSWORD, ROLE_ADMIN));
//        userDetailsList.add(createUserDetails(USER_LOGIN, USER_PASSWORD, ROLE_USER));
//
//        return new InMemoryUserDetailsManager(userDetailsList);
//    }

    private ReactiveAuthenticationManager createReactiveAuthenticationManager() {
//        var userDetailsService = userDetailsService();
//        UserDetails adminDetails = userDetailsService.loadUserByUsername(ADMIN_LOGIN);
//        UserDetails userDetails = userDetailsService.loadUserByUsername(USER_LOGIN);
//
//        var mapReactiveUserDetailsService = new MapReactiveUserDetailsService(adminDetails, userDetails);
//
//        return new UserDetailsRepositoryReactiveAuthenticationManager(mapReactiveUserDetailsService);


        UserDetails adminDetails = createUserDetails(ADMIN_LOGIN, ADMIN_PASSWORD, ROLE_ADMIN);
        UserDetails userDetails = createUserDetails(USER_LOGIN, USER_PASSWORD, ROLE_USER);

        var mapReactiveUserDetailsService = new MapReactiveUserDetailsService(adminDetails, userDetails);

        return new UserDetailsRepositoryReactiveAuthenticationManager(mapReactiveUserDetailsService);
    }

    private UserDetails createUserDetails(String username, String password, String role) {
        return User.withUsername(username)
                .password(password)
                .roles(role)
                .build();
    }
}
