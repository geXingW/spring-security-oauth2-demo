package com.gexingw.oauth2.auth.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.gexingw.oauth2.auth.entity.User;
import org.apache.ibatis.annotations.Mapper;

/**
 * spring-security-oauth2-demo.
 *
 * @author GeXingW
 * @date 2023/7/6 11:01
 */
@Mapper
public interface UserMapper extends BaseMapper<User> {


}
