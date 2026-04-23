package com.example.algamoney.api.resource;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenResourceTokens {

	private final JwtEncoder jwtEncoder;

	public TokenResourceTokens(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}

	@PostMapping("/login/token")
	public OAuth2AccessTokenResponse generateToken(@RequestParam String username) {

		Instant now = Instant.now();
		long expiresIn = 20 * 60; // 20 min

		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer("http://localhost:8080")
				.issuedAt(now)
				.expiresAt(now.plusSeconds(expiresIn))
				.subject(username)
				.claim("roles", List.of("ROLE_USER"))
				.claim("scope", List.of("read", "write"))
				.claim("client_id", "angular")
				.build();

		String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims))
				.getTokenValue();
		String refreshToken = UUID.randomUUID()
				.toString();

		return OAuth2AccessTokenResponse.withToken(accessToken)
				.tokenType(org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER)
				.scopes(Set.of("read", "write"))
				.refreshToken(refreshToken)
				.expiresIn(expiresIn)
				.build();
	}
}