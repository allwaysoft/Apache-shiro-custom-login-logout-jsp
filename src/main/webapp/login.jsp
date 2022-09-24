<%--
  Created by IntelliJ IDEA.
  User: Administrator
  Date: 2018/7/24
  Time: 22:56
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
    <head>
        <title>Title</title>
    </head>
    <body>
        <h1>用户登陆</h1>
        <div style="color: red">${message}</div>
        <form action="login.do" method="post">
            帐号：<input type="text" name="username"><br>
            密码：<input type="password" name="password"><br>
            <input type="submit" value="确定">
            <input type="reset" value="重置">
        </form>
    </body>
</html>