<%@page language="java" pageEncoding="UTF-8"%>
<%@page contentType="text/html;charset=UTF-8"%>
<%    request.setCharacterEncoding("UTF-8");
    response.setCharacterEncoding("UTF-8");
    response.setContentType("text/html; charset=UTF-8");
%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@page import="java.sql.*"%>
<%@page import="java.io.*"%>
<%@page import="java.sql.DriverManager"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.Statement"%>
<%@page import="java.sql.Connection"%>
<%@page import="java.security.MessageDigest"%>
<%@page import="java.security.NoSuchAlgorithmException"%>
<%@page import="java.security.NoSuchProviderException"%>
<%@page import="java.security.SecureRandom"%>

<%@page import="nl.captcha.Captcha"%>

<%@page import="java.security.*"%>
<%@page import="java.security.spec.InvalidKeySpecException"%>
<%@page import="java.security.spec.PKCS8EncodedKeySpec"%>
<%@page import="java.security.spec.X509EncodedKeySpec"%>
<%@page import="java.util.Base64"%>

<%@page import="javax.crypto.BadPaddingException"%>
<%@page import="javax.crypto.Cipher"%>
<%@page import="javax.crypto.IllegalBlockSizeException"%>
<%@page import="javax.crypto.NoSuchPaddingException"%>

<%@ page import="org.apache.shiro.SecurityUtils" %>

<%@ page import ="org.apache.shiro.authc.AuthenticationException" %>
<%@ page import ="org.apache.shiro.authc.UsernamePasswordToken" %>
<%@ page import ="org.apache.shiro.subject.Subject" %>


<%
    Captcha captcha = (Captcha) session.getAttribute(Captcha.NAME);
    System.out.println(captcha.getAnswer());
    request.setCharacterEncoding("UTF-8");
    String answer = request.getParameter("answer");
    boolean result = captcha.isCorrect(answer);
    session.removeAttribute(Captcha.NAME);

    if (result) {

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        try {
            subject.login(token);
            request.getSession().setAttribute("username", username);
            response.sendRedirect(response.encodeURL("home.jsp"));
        } catch (AuthenticationException e) {
            response.sendRedirect(response.encodeURL("index.jsp"));
        }
    } else {
        response.sendRedirect(response.encodeURL("index.jsp"));
    }
%>