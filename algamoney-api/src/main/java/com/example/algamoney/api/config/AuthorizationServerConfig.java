package com.example.algamoney.api.config;

import java.time.Duration;
import java.util.UUID;

import org.junit.jupiter.api.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Bean
	@Order(1)
	public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher()).with(authorizationServerConfigurer,
				Customizer.withDefaults());

		http.exceptionHandling(
				exceptions -> exceptions.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));

		return http.build();

	}

	@Bean
	@Order(2)
	public SecurityFilterChain resourceServer(HttpSecurity http) throws Exception {

		return http.securityMatcher("/**")
				.authorizeHttpRequests(
						auth -> auth.requestMatchers("/categorias").permitAll().anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())).build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {

		RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("angular")
				.clientSecret(passwordEncoder.encode("@ngul@r0"))
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("read").scope("write")
				.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(30)).build()).build();

		return new InMemoryRegisteredClientRepository(client);
	}

}
