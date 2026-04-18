package com.example.algamoney.api.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher()).with(authorizationServerConfigurer,
				(authorizationServer) -> authorizationServer.oidc(Customizer.withDefaults()) // opcional
		).authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()));

		return http.build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository(PasswordEncoder encoder) {

		RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("angular")
				.clientSecret(encoder.encode("@ngul@r0"))
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("read").scope("write")
				.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(30)).build()).build();

		return new InMemoryRegisteredClientRepository(client);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {

		KeyPair keyPair = generateRsaKey();

		RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate()).keyID(UUID.randomUUID().toString()).build();

		JWKSet jwkSet = new JWKSet(rsaKey);

		return new ImmutableJWKSet<>(jwkSet);
	}

	private static KeyPair generateRsaKey() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/*
	 * @Bean public AuthorizationServerSettings authorizationServerSettings() {
	 * return AuthorizationServerSettings.builder().build(); }
	 */
}
