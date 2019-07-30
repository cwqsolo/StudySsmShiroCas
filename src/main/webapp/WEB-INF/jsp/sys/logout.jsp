<%@ page language="java" import="java.util.*" pageEncoding="utf-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<%
    String path = request.getContextPath();
    String basePath = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + path + "/";
%>

<h2>您退出系统！！！</h2>
<p></p>
<form id="loginform" action="<%=basePath %>/user/logout" method="post">
    <button type="submit">退出登录</button>
</form>


