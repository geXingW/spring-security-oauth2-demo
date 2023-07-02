package com.gexingw.oauth2.auth.provider;

import com.gexingw.oauth2.auth.token.OAuth2PasswordAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/7/2 11:22
 */
public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService oAuth2AuthorizationService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final UserDetailsService userDetailsService;

    public final static String GRANT_TYPE_PASSWORD = "password";

    public OAuth2PasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, UserDetailsService userDetailsService) {
        this.oAuth2AuthorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        UserDetails userDetails = this.userDetailsService.loadUserByUsername("user");
//        if (userDetails == null) {
//            throw new RuntimeException("用户名密码错误!");
//        }

        OAuth2ClientAuthenticationToken principal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        RegisteredClient registeredClient = principal.getRegisteredClient();
        if (registeredClient == null) {
            throw new RuntimeException("Client信息错误!");
        }

        // 生成AccessToken
        DefaultOAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder().registeredClient(registeredClient)
                .principal(principal).tokenType(OAuth2TokenType.ACCESS_TOKEN).authorizedScopes(registeredClient.getScopes())
                .authorizationGrantType(new AuthorizationGrantType(GRANT_TYPE_PASSWORD)).build();
        OAuth2Token accessToken = tokenGenerator.generate(accessTokenContext);
        if (accessToken == null) {
            throw new RuntimeException("AccessToken生成失败!");
        }
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken.getTokenValue(), accessToken.getIssuedAt(), accessToken.getExpiresAt(), accessTokenContext.getAuthorizedScopes());

        // 生成refreshToken
        DefaultOAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder().registeredClient(registeredClient)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN).authorizationGrantType(new AuthorizationGrantType(GRANT_TYPE_PASSWORD))
                .build();
        OAuth2Token refreshToken = tokenGenerator.generate(refreshTokenContext);
        if (refreshToken == null) {
            throw new RuntimeException("RefreshToken生成失败!");
        }
        OAuth2RefreshToken oAuth2RefreshToken = (OAuth2RefreshToken) refreshToken;

        oAuth2AuthorizationService.save(
                OAuth2Authorization.withRegisteredClient(registeredClient).principalName(authentication.getName())
                        .authorizationGrantType(new AuthorizationGrantType(GRANT_TYPE_PASSWORD))
                        .accessToken(oAuth2AccessToken).refreshToken(oAuth2RefreshToken).build()
        );

        SecurityContextHolder.clearContext();

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, principal, oAuth2AccessToken, oAuth2RefreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
