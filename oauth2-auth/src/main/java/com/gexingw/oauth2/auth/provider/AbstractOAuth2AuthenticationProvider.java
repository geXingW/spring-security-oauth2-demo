package com.gexingw.oauth2.auth.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
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
 * @date 2023/7/5 22:24
 */
public abstract class AbstractOAuth2AuthenticationProvider implements AuthenticationProvider {

    protected final OAuth2AuthorizationService oAuth2AuthorizationService;

    protected final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    protected final UserDetailsService userDetailsService;

    protected final PasswordEncoder passwordEncoder;

    public AbstractOAuth2AuthenticationProvider(OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.oAuth2AuthorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken principal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        RegisteredClient registeredClient = principal.getRegisteredClient();
        if (registeredClient == null) {
            throw new RuntimeException("客户端信息错误！");
        }

        Authentication authenticatedInfo = this.getAuthenticatedInfo(authentication);

        // RefreshToken
//        OAuth2Authorization.Builder = OAuth2Authorization.withRegisteredClient(registeredClient).attribute(, authenticatedInfo)

        DefaultOAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder().registeredClient(registeredClient)
                .principal(authenticatedInfo).tokenType(OAuth2TokenType.ACCESS_TOKEN).authorizedScopes(registeredClient.getScopes())
                .authorizationGrantType(new AuthorizationGrantType(this.getGrantType())).build();
        OAuth2Token accessToken = tokenGenerator.generate(accessTokenContext);
        if (accessToken == null) {
            throw new RuntimeException("AccessToken生成失败!");
        }

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken.getTokenValue(), accessToken.getIssuedAt(), accessToken.getExpiresAt(), accessTokenContext.getAuthorizedScopes());

        // 生成refreshToken
        DefaultOAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder().registeredClient(registeredClient)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN).authorizationGrantType(new AuthorizationGrantType(this.getGrantType()))
                .build();
        OAuth2Token refreshToken = tokenGenerator.generate(refreshTokenContext);
        if (refreshToken == null) {
            throw new RuntimeException("RefreshToken生成失败!");
        }
        OAuth2RefreshToken oAuth2RefreshToken = (OAuth2RefreshToken) refreshToken;

        oAuth2AuthorizationService.save(
                OAuth2Authorization.withRegisteredClient(registeredClient).principalName(authentication.getName())
                        .authorizationGrantType(new AuthorizationGrantType(this.getGrantType()))
                        .accessToken(oAuth2AccessToken).refreshToken(oAuth2RefreshToken).build()
        );

        SecurityContextHolder.clearContext();

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, principal, oAuth2AccessToken, oAuth2RefreshToken);
    }

    @Override
    public abstract boolean supports(Class<?> authentication);

    protected abstract Authentication getAuthenticatedInfo(Authentication authentication);

    protected abstract String getGrantType();

}
