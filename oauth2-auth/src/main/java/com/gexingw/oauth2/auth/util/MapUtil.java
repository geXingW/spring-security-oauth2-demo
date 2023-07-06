package com.gexingw.oauth2.auth.util;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/7/2 21:58
 */
public class MapUtil {

    public static Map<String, Object> getRequestParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        Map<String, Object> parameters = new HashMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.put(key, value);
            }
        });
        return parameters;
    }

}
