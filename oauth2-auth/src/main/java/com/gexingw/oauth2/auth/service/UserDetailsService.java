package com.gexingw.oauth2.auth.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.gexingw.oauth2.auth.entity.User;
import com.gexingw.oauth2.auth.mapper.UserMapper;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/7/6 11:00
 */
@Service
@AllArgsConstructor
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userMapper.selectOne(new QueryWrapper<User>().eq("username", username));
    }

}
