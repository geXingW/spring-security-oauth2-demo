package com.gexingw.oauth2.auth.convert;

import com.gexingw.oauth2.auth.provider.OAuth2PasswordAuthenticationProvider;
import com.gexingw.oauth2.auth.token.OAuth2PasswordAuthenticationToken;
import com.gexingw.oauth2.auth.util.MapUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/7/2 11:36
 */
public class OAuth2PasswordAuthenticationConvert implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!OAuth2PasswordAuthenticationProvider.GRANT_TYPE_PASSWORD.equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }


        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> parameters = MapUtil.getRequestParameters(request);

        // 判断scope
//        String scope = parameters.get(OAuth2ParameterNames.SCOPE);
//        if (StringUtils.hasText(scope) &&
//                parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
//
//            OAuth2EndpointUtils.throwError(
//                    OAuth2ErrorCodes.INVALID_REQUEST,
//                    OAuth2ParameterNames.SCOPE,
//                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
//        }
//
//        HashMap<String, Object> additionParameters = new HashMap<>(parameters.size());
//        additionParameters.putAll(parameters);



        return new OAuth2PasswordAuthenticationToken(clientPrincipal, parameters);
    }

}
