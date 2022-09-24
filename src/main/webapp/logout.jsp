<%@ page import="org.apache.shiro.SecurityUtils" %>

<%@ page import ="org.apache.shiro.authc.AuthenticationException" %>
<%@ page import ="org.apache.shiro.authc.UsernamePasswordToken" %>
<%@ page import ="org.apache.shiro.subject.Subject" %>
<%

    Subject subject = SecurityUtils.getSubject();
    subject.logout();
    response.sendRedirect("index.jsp");
%>
