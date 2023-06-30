package com.gexingw.oauth2.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/6/30 21:45
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

}
