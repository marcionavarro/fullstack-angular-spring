package com.example.algamoney.api;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.example.algamoney.api.model.Usuario;
import com.example.algamoney.api.repository.UsuarioRespository;
import com.example.algamoney.api.security.UsuarioSistema;

@Configuration
@Profile("basic-security")
public class BasicSecurityConfig {

	@Autowired
	private UsuarioRespository usuarioRepository;

	@Bean
	public UserDetailsService userDetailsService() {
		return username -> {

			System.out.println("LOGIN: " + username);

			Usuario usuario = usuarioRepository.findByEmail(username)
					.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));

			var authorities = usuario.getPermissoes()
					.stream()
					.map(p -> new SimpleGrantedAuthority(p.getDescricao()))
					.toList();

			System.out.println("AUTHORITIES: " + authorities);

			return new UsuarioSistema(usuario, authorities);
		};
	}

	@Bean
	public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder) {

		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder);

		return provider;
	}

	// 🔐 BASIC CHAIN
	@Bean
	@Order(3)
	public SecurityFilterChain basicChain(HttpSecurity http, AuthenticationProvider authenticationProvider)
			throws Exception {

		http.securityMatcher(request -> request.getHeader("Authorization") != null && request.getHeader("Authorization")
				.startsWith("Basic"));

		http.authenticationProvider(authenticationProvider)
				.authorizeHttpRequests(auth -> auth.anyRequest()
						.authenticated())
				.httpBasic(withDefaults())
				.csrf(csrf -> csrf.disable());

		return http.build();
	}
}
