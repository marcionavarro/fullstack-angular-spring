package com.example.algamoney.api.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;

@Configuration
@Profile("oauth2-security")
public class KeyConfig {

	// 🔑 Gera chave RSA (privada + pública)
	@Bean
	public RSAKey rsaKey() {
		KeyPair keyPair = generateKeyPair();

		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID(UUID.randomUUID()
						.toString())
				.build();
	}

	// 🔑 Expõe apenas a chave pública (Resource Server usa isso)
	@Bean
	public RSAPublicKey rsaPublicKey(RSAKey rsaKey) throws JOSEException {
		return rsaKey.toRSAPublicKey();
	}

	// 🔑 Necessário para o Authorization Server (JWK endpoint)
	@Bean
	public JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource(RSAKey rsaKey) {
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (selector, context) -> selector.select(jwkSet);
	}

	// ⚙️ Config padrão do Authorization Server
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				.build();
	}

	// 🔧 Geração do par de chaves
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