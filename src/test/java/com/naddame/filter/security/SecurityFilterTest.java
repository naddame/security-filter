package com.naddame.filter.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class SecurityFilterTest {

    private String authUrl = "http://pl-dev.cloudapp.net/ProductLiveTest/rest/api/rest/checkLogin";
    private String authTokenName = "Auth-Token";
    private String valideToken = "morgan@product-live.com:1497203949980:13d5f0979c7227698c92e9187c28c18c";

    @Test
    public void testDoFilterAuthSuccess() throws ServletException, IOException {

        SecurityFilter filter = new SecurityFilter();

        HttpServletRequest mockReq = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
        FilterChain mockFilterChain = Mockito.mock(FilterChain.class);
        FilterConfig mockFilterConfig = Mockito.mock(FilterConfig.class);
        Mockito.when(mockFilterConfig.getInitParameter("authUrl")).thenReturn(authUrl);
        Mockito.when(mockFilterConfig.getInitParameter("authTokenName")).thenReturn(authTokenName);
        // mock the getRequestURI() response
        Mockito.when(mockReq.getHeader("Auth-Token")).thenReturn(valideToken);
        ServletOutputStream os = Mockito.mock(ServletOutputStream.class);
        Mockito.when(mockResp.getOutputStream()).thenReturn(os);
        filter.init(mockFilterConfig);
        filter.doFilter(mockReq, mockResp, mockFilterChain);
        filter.destroy();
    }

    @Test
    public void testDoFilterAuthFail() throws ServletException, IOException {

        SecurityFilter filter = new SecurityFilter();

        HttpServletRequest mockReq = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
        FilterChain mockFilterChain = Mockito.mock(FilterChain.class);
        FilterConfig mockFilterConfig = Mockito.mock(FilterConfig.class);
        Mockito.when(mockFilterConfig.getInitParameter("authUrl")).thenReturn(authUrl);
        Mockito.when(mockFilterConfig.getInitParameter("authTokenName")).thenReturn(authTokenName);

        // mock the getRequestURI() response
        Mockito.when(mockReq.getHeader("Auth-Token")).thenReturn("fail:1497203949980:detyeyze");
        ServletOutputStream os = Mockito.mock(ServletOutputStream.class);
        Mockito.when(mockResp.getOutputStream()).thenReturn(os);
        filter.init(mockFilterConfig);

        filter.doFilter(mockReq, mockResp, mockFilterChain);
        filter.destroy();

    }

    @Test(expected = Exception.class)
    public void testDoFilterThrowConfigException() throws ServletException, IOException {

        SecurityFilter filter = new SecurityFilter();

        HttpServletRequest mockReq = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
        FilterChain mockFilterChain = Mockito.mock(FilterChain.class);
        FilterConfig mockFilterConfig = Mockito.mock(FilterConfig.class);

        // mock the getRequestURI() response
        Mockito.when(mockReq.getHeader("Auth-Token")).thenReturn("fail:1497203949980:detyeyze");
        ServletOutputStream os = Mockito.mock(ServletOutputStream.class);
        Mockito.when(mockResp.getOutputStream()).thenReturn(os);
        filter.init(mockFilterConfig);

        filter.doFilter(mockReq, mockResp, mockFilterChain);
        filter.destroy();
    }

    @Test(expected = Exception.class)
    public void testDoFilterThrowUrlNotReachableException() throws ServletException, IOException {

        SecurityFilter filter = new SecurityFilter();

        HttpServletRequest mockReq = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
        FilterChain mockFilterChain = Mockito.mock(FilterChain.class);
        FilterConfig mockFilterConfig = Mockito.mock(FilterConfig.class);
        // mock the getRequestURI() response
        Mockito.when(mockFilterConfig.getInitParameter("authUrl")).thenReturn("http://hostnamenotreachabletest/");
        Mockito.when(mockFilterConfig.getInitParameter("authTokenName")).thenReturn(authTokenName);
        Mockito.when(mockReq.getHeader("Auth-Token")).thenReturn("fail:1497203949980:detyeyze");
        ServletOutputStream os = Mockito.mock(ServletOutputStream.class);
        Mockito.when(mockResp.getOutputStream()).thenReturn(os);
        filter.init(mockFilterConfig);
        filter.doFilter(mockReq, mockResp, mockFilterChain);
        filter.destroy();
    }


}
