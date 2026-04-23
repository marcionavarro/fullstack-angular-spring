package com.example.algamoney.api.token;

import java.time.Duration;
import java.util.Map;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import com.example.algamoney.api.config.property.AlgamoneyApiProperty;

@ControllerAdvice
public class RefreshTokenPostProcessor implements ResponseBodyAdvice<OAuth2AccessTokenResponse> {

	@Autowired
	private AlgamoneyApiProperty algamoneyApiProperty;
	
    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        // Aplica apenas no endpoint de token
        return returnType.getMethod() != null && returnType.getMethod().getName().equals("accessTokenResponse");
    }

    @Override
    public OAuth2AccessTokenResponse beforeBodyWrite(
            OAuth2AccessTokenResponse body,
            MethodParameter returnType,
            MediaType selectedContentType,
            Class<? extends HttpMessageConverter<?>> selectedConverterType,
            ServerHttpRequest request,
            ServerHttpResponse response) {

        HttpServletRequest req = ((ServletServerHttpRequest) request).getServletRequest();
        HttpServletResponse resp = ((ServletServerHttpResponse) response).getServletResponse();

        // Se existir refresh token, adiciona cookie e remove do body
        if (body.getRefreshToken() != null) {
            String refreshTokenValue = body.getRefreshToken().getTokenValue();
            adicionarRefreshTokenNoCookie(refreshTokenValue, req, resp);

            // Remove refresh token do body
            body = OAuth2AccessTokenResponse.withToken(body.getAccessToken().getTokenValue())
                    .tokenType(body.getAccessToken().getTokenType())
                    .scopes(body.getAccessToken().getScopes())
                    .expiresIn(Duration.between(body.getAccessToken().getIssuedAt(), body.getAccessToken().getExpiresAt()).getSeconds())
                    .build();
        }

        return body;
    }

    private void adicionarRefreshTokenNoCookie(String refreshToken, HttpServletRequest req, HttpServletResponse resp) {
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(algamoneyApiProperty.getSeguranca().isEnableHttps());
        refreshTokenCookie.setPath(req.getContextPath() + "/oauth2/token");
        refreshTokenCookie.setMaxAge(30 * 24 * 60 * 60); // 30 dias
        resp.addCookie(refreshTokenCookie);
    }
}