package com.gexingw.oauth2.auth.provider;

import com.gexingw.oauth2.auth.token.OAuth2PasswordAuthenticationToken;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.util.ArrayList;
import java.util.Map;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/7/2 11:22
 */
public class OAuth2PasswordAuthenticationProvider extends AbstractOAuth2AuthenticationProvider {

    public final static String GRANT_TYPE_PASSWORD = "password";

    public final static String PARAM_USERNAME = "username";

    public final static String PARAM_PASSWORD = "password";

    public OAuth2PasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        super(authorizationService, tokenGenerator, userDetailsService, passwordEncoder);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    protected Authentication getAuthenticatedInfo(Authentication authentication) {
        OAuth2PasswordAuthenticationToken passwordAuthentication = (OAuth2PasswordAuthenticationToken) authentication;

        // 查询登录信息并校验
        Map<String, Object> parameters = passwordAuthentication.getAdditionalParameters();
        String username = (String) parameters.get(PARAM_USERNAME);
        if (StringUtils.isBlank(username)) {
            throw new RuntimeException("用户名不能为空！");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null) {
            throw new RuntimeException("用户名或密码错误！");
        }

        if (!passwordEncoder.matches(parameters.get(PARAM_PASSWORD).toString(), userDetails.getPassword())) {
            throw new RuntimeException("用户名或密码错误！");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), new ArrayList<>());
    }

    @Override
    protected String getGrantType() {
        return GRANT_TYPE_PASSWORD;
    }

}
