package com.czertainly.core.config;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.DispatcherType;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.stream.Collectors;

@Component
public class RequestResponseInterceptor implements HandlerInterceptor {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (DispatcherType.REQUEST.name().equals(request.getDispatcherType().name())
                && request.getMethod().equals(HttpMethod.GET.name())) {
            ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
            requestWrapper.getParameterMap();
            ToStringBuilder debugMessage = new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                    .append("METHOD", requestWrapper.getMethod())
                    .append("PATH", requestWrapper.getRequestURI())
                    .append("FROM", requestWrapper.getRemoteAddr())
                    .append("REQUEST TYPE", requestWrapper.getContentType())
                    .append("REQUEST HEADERS", Collections.list(requestWrapper.getHeaderNames()).stream()
                            .map(r -> r + " : " + requestWrapper.getHeader(r)).collect(Collectors.toList()));
            logger.debug("REQUEST DATA: {}", debugMessage);
        }
        return true;
    }
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) throws Exception {
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        ToStringBuilder debugMessage = new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("RESPONSE FOR", request.getRequestURI())
                .append("RESPONSE STATUS", responseWrapper.getStatus())
                .append("RESPONSE TYPE", responseWrapper.getContentType())
                .append("RESPONSE HEADERS", responseWrapper.getHeaderNames().stream()
                        .map(r -> r + " : " + responseWrapper.getHeaders(r)).collect(Collectors.toList()))
                .append("RESPONSE BODY", new String(responseWrapper.getContentAsByteArray()));
        logger.debug("RESPONSE DATA: {}", debugMessage);
        responseWrapper.copyBodyToResponse();

    }
}
