<%@page import="java.net.HttpCookie"%>
<%@ page language="java" pageEncoding="UTF-8"%>
<%@ page contentType="text/html;charset=UTF-8"%>
<%
    request.setCharacterEncoding("UTF-8");
    response.setCharacterEncoding("UTF-8");
    response.setContentType("text/html; charset=UTF-8");
%>



<!DOCTYPE html>
<html>
    <head>
        <title>请登录</title>

        <script src="jsencrypt.min.js"></script>

        <script type="text/javascript">
            function reloadImg() {
                var timestamp = new Date().getTime();
                document.getElementById("captcha").src = "simpleCaptcha.jpg?"
                        + timestamp;
            }


        </script>

        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
        <meta http-equiv="Pragma" content="no-cache" />
        <meta http-equiv="Expires" content="0" />
        <link href="bootstrap-5.1.3-dist/css/bootstrap.min.css" rel="stylesheet" >
        <script src="bootstrap-5.1.3-dist/js/bootstrap.bundle.min.js"></script>
        <link href="bootstrap-icons-1.8.3/bootstrap-icons.css" rel="stylesheet">
    </head>
    <body>
        <form autocomplete="off" id="form" method="post" action="<%=response.encodeURL("validate.jsp")%>"
              >

            <div class="container-fluid vh-100" style="margin-top:50px">
                <div class="" style="margin-top:50px">
                    <div class="rounded d-flex justify-content-center">
                        <div class=" col-md-4 col-sm-12 shadow-lg p-5 bg-light">
                            <div class="text-center">
                                <h3 class="text-primary">请登录</h3>
                            </div>
                            <div class="p-4">

                                <div class="input-group mb-3">
                                    <span class="input-group-text bg-secondary"><i
                                            class="bi bi-person-fill text-white"></i></span>
                                    <input id="username" type="text" name="username" required class="form-control" placeholder="用户名">
                                </div>
                                <div class="input-group mb-3">
                                    <span class="input-group-text bg-secondary"><i
                                            class="bi bi-key-fill text-white"></i></span>
                                    <input id="password" type="password" name="password"
                                           required class="form-control" placeholder="密码">
                                </div>
                                <div class="input-group mb-3">
                                    <span class="input-group-text bg-secondary"><i
                                            class="bi bi-lock-fill text-white"></i></span>
                                    <input type="text" name="answer" class="form-control" placeholder="输入下图中的校验码">
                                </div>
                                <div class="input-group mb-3">
                                    <span class="input-group-text bg-secondary"><i
                                            class="bi bi-image-fill text-white"></i></span>
                                    <img id="captcha" src="simpleCaptcha.jpg" alt="CAPTCHA Image" class="img-responsive captchaImg"><button type="button" onclick="javascript:reloadImg()" class="btn btn-outline-blue"><i
                                            class="bi bi-arrow-repeat text-black"></i>
                                    </button>
                                </div>
                                <div class="col-12">
                                    <button type="submit" class="btn btn-primary px-4 float-end mt-4">登录</button>
                                </div>

                            </div>
                        </div>
                    </div>
                </div>
            </div>


        </form>

    </body>
</html>

