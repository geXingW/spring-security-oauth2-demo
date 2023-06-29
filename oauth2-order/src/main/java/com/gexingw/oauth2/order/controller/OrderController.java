package com.gexingw.oauth2.order.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/6/29 13:38
 */
@RestController
@RequestMapping("order")
public class OrderController {

    @GetMapping
    public Object index(){
        return "Order controller index.";
    }
}
