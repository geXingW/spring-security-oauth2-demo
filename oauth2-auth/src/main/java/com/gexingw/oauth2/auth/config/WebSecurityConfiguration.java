package com.gexingw.oauth2.auth.config;

import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashMap;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/6/27 13:33
 */
@Configuration
public class WebSecurityConfiguration {

    @Bean
    @Order(2)
    @SneakyThrows
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity httpSecurity) {
        httpSecurity.authorizeHttpRequests(
                authorize -> authorize
                        .antMatchers("/assets/**", "/login", "/favicon.ico").permitAll()
                        .anyRequest().authenticated()
        );

        // 自定义登录页面
        httpSecurity.formLogin(formLogin -> formLogin.loginPage("/login"));

        // 启用授权码模式的表单登录
//        httpSecurity.formLogin(Customizer.withDefaults());

        // 禁用密码模式的表单登录
//        httpSecurity.formLogin().disable();

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        HashMap<String, PasswordEncoder> passwordEncoderMap = new HashMap<>(1);
        passwordEncoderMap.put("bcrypt", new BCryptPasswordEncoder());

        return new DelegatingPasswordEncoder("bcrypt", passwordEncoderMap);
    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.builder()
//                .username("user")
//                .password(passwordEncoder().encode("password"))
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(userDetails);
//    }

}
