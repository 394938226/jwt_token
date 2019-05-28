package com.example.demo.conf.security;

import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;

public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {
    static final String TOKEN_PREFIX = "Bearer";
    static final String HEADER_STRING = "Authorization";
    private Logger log = LoggerFactory.getLogger(JWTLoginFilter.class);

    public JWTLoginFilter(AuthenticationManager authManager) {
        //配置只有访问/api/login时，这个过滤器才会起作用
        super(new AntPathRequestMatcher("/api/login", "POST"));
        setAuthenticationManager(authManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        JSONObject params;
        try {
            String jsonparam = StreamUtils.copyToString(request.getInputStream(), Charset.forName("utf-8"));
            params = JSONObject.parseObject(jsonparam);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationServiceException("读取登录请求参数异常");
        }


        String username = null;
        String password = null;
        if (params != null) {
            username = params.getString("username");
            password = params.getString("password");
        }

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain, Authentication auth) throws IOException, ServletException {
        TokenAuthenticationHandler tokenAuthenticationHandler = new TokenAuthenticationHandler();
        Object obj = auth.getPrincipal();
        if (obj != null) {
            UserDetails userDetails = (UserDetails) obj;
            String token = tokenAuthenticationHandler.generateToken(JSONObject.toJSONString(userDetails));
            res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + token);
            //todo 将最新生成的token保存在redis或是数据库中，可以在JWTAuthenticationFilter中判断提交上来的token和当前数据库中的token是否一致
            //todo ，如果不一致则说明客户端没有使用最新的token

        }
    }
}
