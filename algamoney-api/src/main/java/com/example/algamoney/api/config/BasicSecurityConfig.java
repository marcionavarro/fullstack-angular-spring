package com.example.algamoney.api.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.example.algamoney.api.model.Usuario;
import com.example.algamoney.api.repository.UsuarioRespository;
import com.example.algamoney.api.security.UsuarioSistema;

@Configuration
@Profile("basic-security")
@EnableMethodSecurity(prePostEnabled = true)  // Habilita segurança baseada em métodos
public class BasicSecurityConfig {
    @Autowired
    private UsuarioRespository usuarioRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            Usuario usuario = usuarioRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));

            // Adiciona um log para ver as permissões do usuário
            System.out.println("Permissões do usuário: " + usuario.getPermissoes());

            // Converte as permissões para authorities
            var authorities = usuario.getPermissoes()
                    .stream()
                    .map(p -> {
                        String role = p.getDescricao();
                        System.out.println("Role mapeada: " + role);
                        return new SimpleGrantedAuthority(role);  // Certifique-se de que a role tem o formato correto
                    })
                    .toList();

            System.out.println("Authorities mapeadas: ");
            authorities.forEach(authority -> System.out.println(authority.getAuthority()));
            
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

    // Configuração de segurança para Basic Auth
    @Bean
    public SecurityFilterChain basicSecurity(HttpSecurity http, AuthenticationProvider authenticationProvider)
            throws Exception {
    	
        http
            .securityMatcher("/**")
            .authenticationProvider(authenticationProvider)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())  // Requer autenticação para todas as requisições
            .httpBasic(withDefaults())  // Autenticação Básica
            .csrf(csrf -> csrf.disable());  // Desabilita CSRF

        return http.build();
    }
}