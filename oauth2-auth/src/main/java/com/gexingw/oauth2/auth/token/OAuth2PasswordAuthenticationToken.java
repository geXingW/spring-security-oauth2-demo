package com.gexingw.oauth2.auth.token;

import com.gexingw.oauth2.auth.provider.OAuth2PasswordAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/7/2 11:18
 */
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    /**
     * Sub-class constructor.
     *
     * @param clientPrincipal      the authenticated client principal
     * @param additionalParameters the additional parameters
     */
    public OAuth2PasswordAuthenticationToken(Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType(OAuth2PasswordAuthenticationProvider.GRANT_TYPE_PASSWORD), clientPrincipal, additionalParameters);
    }

}
