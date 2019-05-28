package com.example.demo.conf.security;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTAuthenticationFilter extends GenericFilterBean {
    static final String HEADER_STRING = "Authorization";
    static final String TOKEN_PREFIX = "Bearer";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;

        String token = req.getHeader(HEADER_STRING);
        if (StringUtils.isBlank(token) && req.getRequestURI().startsWith("/api")) {
            HttpServletResponse res = (HttpServletResponse) response;
            res.addHeader("Content-Type", "text/html;charset=UTF-8");
            res.setStatus(401);
            res.getWriter().write("{\"error\":\"请提供授权码\"}");
            return;
        }
        if (StringUtils.isNotBlank(token) && token.startsWith(TOKEN_PREFIX)) {
            //todo 从数据库中查询JWTLoginFilter生成的最新token，与当前提交的token对比，如果不一致，则返回token过期错误提示
            TokenAuthenticationHandler tokenAuthenticationHandler = new TokenAuthenticationHandler();
            String subject = tokenAuthenticationHandler.getSubjectFromToken(token.replace(TOKEN_PREFIX, ""));
            if (StringUtils.isBlank(subject)) {
                HttpServletResponse res = (HttpServletResponse) response;
                res.addHeader("Content-Type", "text/html;charset=UTF-8");
                res.setStatus(401);
                res.getWriter().write("{\"error\":\"授权码错误\"}");
                return;
            } else {
                //todo 校验token成功后，如果需要每次访问更新token，可以再次重新生成token，添加到响应头中
                //保存登录信息
                SecurityContextHolder.getContext().setAuthentication(new JWTAuthenticationToken(subject));
            }
        }
        filterChain.doFilter(request, response);
    }
}
