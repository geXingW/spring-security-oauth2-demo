package com.gexingw.oauth2.login.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/6/29 22:01
 */
@Controller
@RequestMapping
public class IndexController {

    @GetMapping
    public String index(Model model, @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
                        @AuthenticationPrincipal OAuth2User oauth2User) {
        System.out.println(authorizedClient.getAccessToken());
        model.addAttribute("authorizedClient", authorizedClient);
        model.addAttribute("oauth2User",oauth2User);
        return "index";
    }

}
