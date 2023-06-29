package com.gexingw.oauth2.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/6/27 14:09
 */
@RestController
public class IndexController {

    @GetMapping
    public Object index(){
        return "Index controller index method.";
    }

}
