package com.example.algamoney.api.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.example.algamoney.api.security.UserDetailsService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

	@Bean
	public AuthenticationProvider authenticationProvider(
	        UserDetailsService userDetailsService,
	        PasswordEncoder passwordEncoder) {
	    DaoAuthenticationProvider provider =
	            new DaoAuthenticationProvider(userDetailsService); // ✅ correto

	    provider.setPasswordEncoder(passwordEncoder);

	    return provider;
	}
	
	@Bean
	@Order(1)
	public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.formLogin(withDefaults())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, AuthenticationProvider authenticationProvider) throws Exception {
		http.securityMatcher("/login", "/logout", "/error")
				.authenticationProvider(authenticationProvider)
				.authorizeHttpRequests(auth -> auth.anyRequest()
						.authenticated())
				.formLogin(withDefaults())
				.logout(logout -> logout.logoutUrl("/logout")
						.invalidateHttpSession(true)
						.deleteCookies("JSESSIONID"));

		return http.build();
	}

	// 👤 USER LOGIN (IMPORTANTE PARA /login FUNCIONAR)
//	@Bean("authUserDetailsService")
//	public UserDetailsService userDetailsService(PasswordEncoder encoder) {
//		return new InMemoryUserDetailsManager(User.withUsername("admin")
//				.password(encoder.encode("admin"))
//				.roles("USER")
//				.build());
//	}

	// Registered client
	@Bean
	public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
		RegisteredClient client = RegisteredClient.withId(UUID.randomUUID()
				.toString())
				.clientId("angular")
				.clientSecret(passwordEncoder.encode("@ngul@r0"))
				.redirectUri("https://oauth.pstmn.io/v1/callback") // Postman
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scope("read")
				.scope("write")
				.tokenSettings(TokenSettings.builder()
//                        .authorizationCodeTimeToLive(Duration.ofMinutes(1)) // 👈 AQUI
//                        .accessTokenTimeToLive(Duration.ofMinutes(30))
						.accessTokenTimeToLive(Duration.ofSeconds(1800))
						.refreshTokenTimeToLive(Duration.ofHours(24))
						.build())
				.build();
		
		 RegisteredClient mobileClient = RegisteredClient.withId(UUID.randomUUID().toString())
		            .clientId("mobile")
		            .clientSecret(passwordEncoder.encode("m0b1l3"))
		            .redirectUri("https://oauth.pstmn.io/v1/callback")
		            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		            .scope("read")
		            .build();

		return new InMemoryRegisteredClientRepository(client, mobileClient);
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			if (context.getTokenType()
					.getValue()
					.equals("access_token")) {
				Authentication principal = context.getPrincipal();

				if (principal != null && principal.getPrincipal()instanceof UserDetails user) {
					JwtClaimsSet.Builder claims = context.getClaims();

					// Substitua sub se quiser, mas não deixe null
					claims.subject(user.getUsername());

					// Não precisa remover audience, deixe padrão
					// claims.audience(...) → opcional

					// Adiciona suas claims extras
					claims.claim("username", user.getUsername());
					claims.claim("roles", user.getAuthorities()
							.stream()
							.map(GrantedAuthority::getAuthority)
							.collect(Collectors.toList()));
					claims.claim("client_id", context.getRegisteredClient()
							.getClientId());
					claims.claim("scope", context.getAuthorizedScopes());

					// exp e jti são gerados automaticamente
				}
			}
		};
	}

//🔑 Bean RSAKey
	@Bean
	public RSAKey rsaKey() {
		KeyPair keyPair = generateKeyPair();
		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID(UUID.randomUUID()
						.toString())
				.build();
	}

	// 🔑 Bean RSAPublicKey exposto para Resource Server
	@Bean
	public RSAPublicKey rsaPublicKey(RSAKey rsaKey) throws JOSEException {
		return rsaKey.toRSAPublicKey();
	}

	// JWKSource necessário pelo Authorization Server
	@Bean
	public JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource(RSAKey rsaKey) {
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				.build();
	}

	// 🔑 Função auxiliar para gerar KeyPair RSA
	private KeyPair generateKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			return generator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}
}