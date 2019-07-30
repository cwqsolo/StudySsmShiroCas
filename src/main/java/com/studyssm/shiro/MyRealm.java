package com.studyssm.shiro;

import com.studyssm.entity.User;
import com.studyssm.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cas.CasAuthenticationException;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.cas.CasToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;


/**
 * Describe:
 *
 * @author cwqsolo  MyRealm ，继承自 CasRealm ，来完成对 CAS Server 返回数据的验证
 * @date 2019/07/22
 */
public class MyRealm  extends CasRealm {

    @Autowired
    private UserService userService;

    private  User us;


    /**
     * 授权，在配有缓存的情况下，只加载一次。
     * @param principal
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
        System.out.println("Myrealm  doGetAuthenticationInfo 1++++");
        //当前登录用户，账号
        us= (User)principal.getPrimaryPrincipal();
        String username = us.getUserName();

        System.out.println("当前登录用户:"+username);
        //获取角色信息
        Set<String> roles = userService.findRoles(username);

        if(roles.size()==0){

            System.out.println("当前用户没有角色！");
        }else
        {
//            for (Role role : roles) {
//                authorizationInfo.addRole(role.getEnname());
//                //获取用户拥有的权限
//                List<Menu> menus = menuService.findByRoleId(role.getId());
//                for(Menu menu : menus){
//                    if(StringUtils.isNotBlank(menu.getPermission())){
//                        authorizationInfo.addStringPermission(menu.getPermission());
//                    }
//                }
//            }
        }

        SimpleAuthorizationInfo simpleAuthenticationInfo  = new SimpleAuthorizationInfo();

        simpleAuthenticationInfo.setRoles(userService.findRoles(username));
        simpleAuthenticationInfo.setStringPermissions(userService.findPermissions(username));

        return simpleAuthenticationInfo ;

    }

    /**
     *  认证登录，查询数据库，如果该用户名正确，得到正确的数据，并返回正确的数据
     * 		AuthenticationInfo的实现类SimpleAuthenticationInfo保存正确的用户信息
     *
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("Myrealm  认证  ++++1");

        CasToken casToken = (CasToken) token;

        // token为空直接返回，页面会重定向到 Cas Server 登录页，并且携带本项目回调页
        if (token == null) {
            System.out.println("Myrealm  认证  token 为空 ++++");
            return null;
        }

        System.out.println("Myrealm  认证  ++++2");
        // 获取服务端范围的票根
        String ticket = (String) casToken.getCredentials();

        // 票根为空直接返回，页面会重定向到 Cas Server 登录页，并且携带本项目回调页
        if (!StringUtils.hasText(ticket)) {
            System.out.println("Myrealm  认证  ticket 为空 ++++");
            return null;
        }

        TicketValidator ticketValidator = ensureTicketValidator();

        try {
            System.out.println("Myrealm  认证  ++++4");
            // 票根验证
            Assertion casAssertion = ticketValidator.validate(ticket, getCasService());
            // 获取服务端返回的用户数据
            AttributePrincipal casPrincipal = casAssertion.getPrincipal();

            System.out.println("Myrealm  认证  ++++5");
            // 拿到用户唯一标识
            String username = casPrincipal.getName();

            // 通过唯一标识查询数据库用户表
            // 如果查询到对应用户则直接返回用户数据
            us = userService.findUserByUsername(username);
            System.out.println("Myrealm  认证  us info="+us.toString());

            //如果没有查询到，抛出异常
            if( us == null ) {
                System.out.println("Myrealm::账户"+username+"不存在！");
                throw new UnknownAccountException("账户"+username+"不存在！");

            }else{
                //如果查询到了，封装查询结果，
                Object principal = us.getUserName();
                Object credentials = us.getPassword();
                String realmName = this.getName();

                // 将获取到的本项目数据库用户包装为 shiro 自身的 principal 存于当前 session 中
                // 之后在整个项目中都可以通过 SecurityUtils.getSubject().getPrincipal() 直接获取到当前用户信息
                List<Object> principals = CollectionUtils.asList(us, casPrincipal.getAttributes());
                PrincipalCollection principalCollection = new SimplePrincipalCollection(principals, getName());

                System.out.println("Myrealm  认证  return sucessfully!!!");
                return new SimpleAuthenticationInfo(principalCollection, ticket);
            }

        } catch (TicketValidationException e) {
            System.out.println("Myrealm  认证  ++++++");
            throw new CasAuthenticationException("Unable to validate ticket [" + ticket + "]", e);
        }


    }

}
