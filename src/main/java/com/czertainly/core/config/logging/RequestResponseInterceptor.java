package com.czertainly.core.config.logging;

import com.czertainly.core.util.SerializationUtil;
import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.ContentCachingRequestWrapper;

import javax.servlet.DispatcherType;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class RequestResponseInterceptor implements HandlerInterceptor {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (logger.isDebugEnabled()) {
            ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
            if (DispatcherType.REQUEST.name().equals(request.getDispatcherType().name())
                    && request.getMethod().equals(HttpMethod.GET.name())) {
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

            if (DispatcherType.REQUEST.name().equals(request.getDispatcherType().name())
                    && request.getMethod().equals(HttpMethod.POST.name()) && request.getRequestURI().startsWith("/api/acme/")) {
                String body = CharStreams.toString(new InputStreamReader(
                        requestWrapper.getInputStream(), Charsets.UTF_8));
                Map<String, String> jws = (Map<String, String>) SerializationUtil.deserialize(body, Map.class);
                if(jws.getOrDefault("payload","").length() <= 3) {
                    ToStringBuilder debugMessage = new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                            .append("METHOD", requestWrapper.getMethod())
                            .append("PATH", requestWrapper.getRequestURI())
                            .append("FROM", requestWrapper.getRemoteAddr())
                            .append("REQUEST TYPE", requestWrapper.getContentType())
                            .append("REQUEST HEADERS", Collections.list(requestWrapper.getHeaderNames()).stream()
                                    .map(r -> r + " : " + requestWrapper.getHeader(r)).collect(Collectors.toList()));
                    logger.debug("REQUEST DATA: {}", debugMessage);
                }
            }
        }
        return true;
    }
}
