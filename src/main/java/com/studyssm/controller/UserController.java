package com.studyssm.controller;

import com.studyssm.entity.User;
import com.studyssm.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cas.CasToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


/**
 * Describe:
 *
 * @author cwqsolo
 * @date 2019/07/24
 */
@Controller
@RequestMapping("user")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    UserService userSer;

    User user;

    /**
     * @param
     * @return
     * @todo 用户登录
     * @since 获取当前用户，
     * 判断用户是否已经认证登录，
     * 用账号密码创建UsernamePasswordToken，
     * 调用subject的login方法
     */
    @RequestMapping(method = RequestMethod.POST, value = "logon")
    public String logon(ServletRequest request, ServletResponse response) throws Exception {

        //获取AuthenticationToken实体
        AuthenticationToken token = createToken(request, response);
        if (token == null) {
            String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                    "must be created in order to execute a login attempt.";
            throw new IllegalStateException(msg);
        }
        try {
            Subject subject = SecurityUtils.getSubject();
            //执行分子系统的Shrio认证与授权
            subject.login(token);
            System.out.println("UserController logon ++++++");

        } catch (AuthenticationException e) {
            e.getMessage();
            e.printStackTrace();
            System.out.println("登录失败");
            return "redirect:/login.jsp";
        }

        return "redirect:/index.jsp";


    }


    @RequestMapping(method = RequestMethod.POST, value = "/shiro-cas")
    protected boolean shirocas(ServletRequest request, ServletResponse response) throws Exception {
        System.out.println("shirocas +++++");

        //获取AuthenticationToken实体
        AuthenticationToken token = createToken(request, response);
        if (token == null) {
            String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                    "must be created in order to execute a login attempt.";
            throw new IllegalStateException(msg);
        }
        try {
            Subject subject = SecurityUtils.getSubject();
            //执行子系统的Shrio认证与授权
            subject.login(token);
            return true;
        } catch (AuthenticationException e) {
            return false;
        }
    }

    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        //获取CAS Server回调请求中的ticket参数,构造CasToken实体,其principal为username,credential为ticket.
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        System.out.println(httpRequest.toString());
        String ticket = httpRequest.getParameter("ticket");
        System.out.println("ticket is=" + ticket);
        return new CasToken(ticket);
    }


    @RequestMapping("/loginSuccess")
    public String loginSuccess() {

        System.out.println("loginSuccess  run++++");
        logger.info("登录成功");

        return "redirect:/index.jsp";
    }

    /**
     * 退出
     *
     * @param session
     * @return
     */
    @RequestMapping("/index")
    public String index(HttpSession session) {
        System.out.println("run  logout....");
        return "redirect:/index.jsp";
    }


    /**
     * 退出
     *
     * @param session
     * @return
     */
    @RequestMapping("/logout")
    public String logout(HttpSession session) {
        System.out.println("run  logout....");
        //session.invalidate();
        Subject subject = SecurityUtils.getSubject();
        //判断当前用户是否已登录
        if (subject.isAuthenticated()) {
            //退出登录
            subject.logout();
            System.out.println("subject.logout!!!");
        }
        return "redirect:http://server.cas.com:8080/cas/logout?service=http://app2.cas.com:8580/node2/shiro-cas";
    }


}
