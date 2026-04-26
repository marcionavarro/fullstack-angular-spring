package com.example.algamoney.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

    // 🔑 JWT
//    @Bean
//    @Order(2)
//    public SecurityFilterChain jwtChain(HttpSecurity http) throws Exception {
//
//        http.securityMatcher(request ->
//                request.getHeader("Authorization") != null &&
//                request.getHeader("Authorization").startsWith("Bearer")
//        );
//
//        http
//            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//            .oauth2ResourceServer(oauth2 -> oauth2.jwt())
//            .csrf(csrf -> csrf.disable());
//
//        return http.build();
//    }
	
	public SecurityFilterChain resourceSecurity(HttpSecurity http) throws Exception {
		http.securityMatcher("/**") // cobre toda a API
				.authorizeHttpRequests(auth -> auth
						.anyRequest()
						.authenticated())
				.csrf(csrf -> csrf.disable())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.oauth2ResourceServer(oauth2 -> oauth2.jwt());

		return http.build();
	}

    // 🚫 FALLBACK
    @Bean
    @Order(4)
    public SecurityFilterChain fallback(HttpSecurity http) throws Exception {

        http
            .securityMatcher("/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().denyAll());

        return http.build();
    }
}