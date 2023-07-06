package com.gexingw.oauth2.auth.entity;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/7/6 11:01
 */
@Data
public class User implements UserDetails, Serializable {

    private Long id;

    /**
     * 账号（手机号）
     */
    private String username;

    /**
     * 密码
     */
    private String password;

    /**
     * 姓名
     */
    private String name;

    /**
     * 手机
     */
    private String phone;

    /**
     * 组织架构id
     */
    private Long deptId;

    /**
     * 用户类型：1、公司员工 2、司机
     */
    private Integer type;

    /**
     * 司机类型：1、运输公司、2、车队联盟  3、个体司机
     */
    private Integer driverType;

    /**
     * 头像
     */
    private String avatar;

    /**
     * 状态:  1 正常 2 禁用
     */
    private Integer status;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new ArrayList<>();
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
