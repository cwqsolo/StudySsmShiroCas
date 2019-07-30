package com.studyssm.mapper;

import com.studyssm.entity.User;

import java.util.List;
import java.util.Set;

public interface UserMapper {

    User findUserByUsername(String username);

    Set<String> findRoles(String username);

    Set<String> findPermissions(String username);

    public List<User> list();
}
