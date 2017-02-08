# create spring filter in web.xml
```code
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns="http://java.sun.com/xml/ns/javaee" xmlns:web="http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
	xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
	id="WebApp_ID" version="2.5">
	<display-name>bizMOB.api.server</display-name>
	
	<context-param>
		<param-name>log4jConfigLocation</param-name>
		<param-value>file:///${bizmob.api.home}/admin/config/log4j.properties</param-value>
	</context-param>
	<context-param>
		<param-name>log4jRefreshInterval</param-name>
		<param-value>60000</param-value>
	</context-param>
	<context-param>
		<param-name>contextConfigLocation</param-name>
		<param-value>
    		file:///${bizmob.api.home}/admin/config/spring/base-config.xml			
    		file:///${bizmob.api.home}/admin/config/spring/datasource.xml
    		file:///${bizmob.api.home}/admin/config/spring/mybatis-context.xml
    		file:///${bizmob.api.home}/admin/config/spring/aop-context.xml
			file:///${bizmob.api.home}/admin/config/spring/*-service-context.xml
		</param-value>
	</context-param>
	
	<filter>
		<filter-name>CharacterEncodingFilter</filter-name>
		<filter-class>org.springframework.web.filter.CharacterEncodingFilter</filter-class>
		<init-param>
			<param-name>encoding</param-name>
			<param-value>UTF-8</param-value>
		</init-param>
		<init-param>
			<param-name>forceEncoding</param-name>
			<param-value>true</param-value>
		</init-param>
	</filter>
	<filter-mapping>
		<filter-name>CharacterEncodingFilter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
	
	<filter>
		<filter-name>HttpMethodFilter</filter-name>
		<filter-class>org.springframework.web.filter.HiddenHttpMethodFilter</filter-class>
	</filter>
	<filter-mapping>
		<filter-name>HttpMethodFilter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
	
	<filter>
		<filter-name>XSSFilter</filter-name>
		<filter-class>com.bizmob.api.base.spring.filter.xss.XSSFilter</filter-class>
	</filter>
	<filter-mapping>
		<filter-name>XSSFilter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
	
	<listener>
		<listener-class>org.springframework.web.util.Log4jConfigListener</listener-class>
	</listener>
	<listener>
		<listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
	</listener>

	<servlet>
		<servlet-name>root</servlet-name>
		<servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
		<init-param>
			<param-name>contextConfigLocation</param-name>
			<param-value>
	  		file:///${bizmob.api.home}/admin/config/spring/mvc-context.xml			
	  </param-value>
		</init-param>
		<load-on-startup>1</load-on-startup>
	</servlet>

	<servlet-mapping>
		<servlet-name>root</servlet-name>
		<url-pattern>/</url-pattern>
	</servlet-mapping>
</web-app>
```
### input below line to your web.xml

```code
	<filter>
		<filter-name>XSSFilter</filter-name>
		<filter-class>com.bizmob.api.base.spring.filter.XSSFilter</filter-class>
	</filter>
	<filter-mapping>
		<filter-name>XSSFilter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
```

# XSS-Filter-Spring

```code
package com.bizmob.api.base.spring.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class XSSFilter implements Filter {

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void destroy() {
    	
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        chain.doFilter(new XSSRequestWrapper((HttpServletRequest) request), response);
    }

}
```

##Apply on not multipart data 
###Filter out xss tag: like script, src, eval

```code
package com.bizmob.api.base.spring.filter;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class XSSRequestWrapper extends HttpServletRequestWrapper {

    public XSSRequestWrapper(HttpServletRequest servletRequest) {
    	super(servletRequest);
    }

    @Override
    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
        if (values == null) {
            return null;
        }

        int count = values.length;
        String[] encodedValues = new String[count];
        for (int i = 0; i < count; i++) {
            encodedValues[i] = stripXSS(values[i]);
        }

        return encodedValues;
    }

    @Override
    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
        return stripXSS(value);
    }

    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        return stripXSS(value);
    }

    private String stripXSS(String value) {
        if (value != null) {
            // NOTE: It's highly recommended to use the ESAPI library and uncomment the following line to
            // avoid encoded attacks.
            // value = ESAPI.encoder().canonicalize(value);

            // Avoid null characters
            value = value.replaceAll("", "");

            // Avoid anything between script tags
            Pattern scriptPattern = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid anything in a src='...' type of expression
            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Remove any lonesome </script> tag
            scriptPattern = Pattern.compile("</script>", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Remove any lonesome <script ...> tag
            scriptPattern = Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid eval(...) expressions
            scriptPattern = Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid expression(...) expressions
            scriptPattern = Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid javascript:... expressions
            scriptPattern = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid vbscript:... expressions
            scriptPattern = Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid onload= expressions
            scriptPattern = Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
        }
        return value;
    }
}
```

###apply on multipart data
### When we work on multipart form data we need to customize on CommonsMultipartResolver

<!-- configure for multipart file upload -->
	<bean id="multipartResolver" class="org.springframework.web.multipart.commons.CommonsMultipartResolver">
		<property name="maxUploadSize" value="#{config['upload.maxUploadSizeInBytes']}" />
		<property name="maxInMemorySize" value="#{config['upload.maxInMemorySizeInBytes']}" />
	</bean>
  
### in spring class library, CommonsMultipartResolver.java below:
```code
....

public class CommonsMultipartResolver extends CommonsFileUploadSupport
		implements MultipartResolver, ServletContextAware {

	private boolean resolveLazily = false;

	...
  
	public boolean isMultipart(HttpServletRequest request) {
		return (request != null && ServletFileUpload.isMultipartContent(request));
	}

	public MultipartHttpServletRequest resolveMultipart(final HttpServletRequest request) throws MultipartException {
		Assert.notNull(request, "Request must not be null");
		if (this.resolveLazily) {
			return new DefaultMultipartHttpServletRequest(request) {
				@Override
				protected void initializeMultipart() {
					MultipartParsingResult parsingResult = parseRequest(request);
					setMultipartFiles(parsingResult.getMultipartFiles());
					setMultipartParameters(parsingResult.getMultipartParameters());
					setMultipartParameterContentTypes(parsingResult.getMultipartParameterContentTypes());
				}
			};
		}
		else {
			MultipartParsingResult parsingResult = parseRequest(request);
			return new DefaultMultipartHttpServletRequest(request, parsingResult.getMultipartFiles(),
					parsingResult.getMultipartParameters(), parsingResult.getMultipartParameterContentTypes());
		}
	}

	...
}
```

###We need to create XSSCommonsMultipartResolver to override and customize

```code
package com.bizmob.api.base.spring.filter;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;

public class XSSCommonsMultipartResolver extends CommonsMultipartResolver {

	private boolean resolveLazily = false;
	
	public XSSCommonsMultipartResolver() {
		super();
	}
	
	public void setResolveLazily(boolean resolveLazily) {
		this.resolveLazily = resolveLazily;
	}
	
	public MultipartHttpServletRequest resolveMultipart(final HttpServletRequest request) throws MultipartException {
		Assert.notNull(request, "Request must not be null");
		if (this.resolveLazily) {
			return new XSSMultipartHttpServletRequest(request) {
				@Override
				protected void initializeMultipart() {
					MultipartParsingResult parsingResult = parseRequest(request);
					setMultipartFiles(parsingResult.getMultipartFiles());
					setMultipartParameters(parsingResult.getMultipartParameters());
					setMultipartParameterContentTypes(parsingResult.getMultipartParameterContentTypes());
				}
			};
		}
		else {
			MultipartParsingResult parsingResult = parseRequest(request);
			return new XSSMultipartHttpServletRequest(request, parsingResult.getMultipartFiles(),
					parsingResult.getMultipartParameters(), parsingResult.getMultipartParameterContentTypes());
		}
	}
}

```

### create XSSMultipartHttpServletRequest to filter data in multipart data

```code
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.MultiValueMap;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.support.DefaultMultipartHttpServletRequest;


public class XSSMultipartHttpServletRequest extends DefaultMultipartHttpServletRequest {

	public XSSMultipartHttpServletRequest(HttpServletRequest request) {
		super(request);
	}
	
	public XSSMultipartHttpServletRequest(HttpServletRequest request, MultiValueMap<String, MultipartFile> mpFiles,
			Map<String, String[]> mpParams, Map<String, String> mpParamContentTypes) {

		super(request);
		setMultipartFiles(mpFiles);
		setMultipartParameters(mpParams);
		setMultipartParameterContentTypes(mpParamContentTypes);
	}
	
	protected Map<String, String[]> getMultipartParameters() {
		Map<String, String[]> result = super.getMultipartParameters();
		Set<String> keySet = result.keySet();
		
		for(String key: keySet){
			String[] values = result.get(key);
			String[] resultValues = new String[values.length];
			for(int i=0; i<values.length; i++) {
				String value = values[i];
				//filter xss below here
				resultValues[i] = stripXSS(value);
			}
			result.put(key, resultValues);
		}
		
		return result;
	}
	
	
	private String stripXSS(String value) {
        if (value != null) {
            // NOTE: It's highly recommended to use the ESAPI library and uncomment the following line to
            // avoid encoded attacks.
            // value = ESAPI.encoder().canonicalize(value);

            // Avoid null characters
            value = value.replaceAll("", "");

            // Avoid anything between script tags
            Pattern scriptPattern = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid anything in a src='...' type of expression
            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Remove any lonesome </script> tag
            scriptPattern = Pattern.compile("</script>", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Remove any lonesome <script ...> tag
            scriptPattern = Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid eval(...) expressions
            scriptPattern = Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid expression(...) expressions
            scriptPattern = Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid javascript:... expressions
            scriptPattern = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid vbscript:... expressions
            scriptPattern = Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid onload= expressions
            scriptPattern = Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
        }
        return value;
    }

}

```

### filter xss:
```code
private final static List<String> MALICIOUS_STRING_LIST = new ArrayList<String>();
	
	static {
		MALICIOUS_STRING_LIST.add("(?i)<.*?script.*?>.*?</.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<.*?script.*?\\s+.*?/script.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<.*?javascript:.*?>.*?</.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<.*?\\s+on.*?>.*?</.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<object.*?>.*?</object.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<.*?object:.*?>.*?</.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<applet.*?>.*?</applet.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<.*?applet:.*?>.*?</.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<embed.*?>.*?</embed.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<.*?embed:.*?>.*?</.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<form.*?>.*?</form.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<.*?form:.*?>.*?</.*?>");
		MALICIOUS_STRING_LIST.add("(?i)<.*?\\f+on.*?>.*?</.*?>");
		
		MALICIOUS_STRING_LIST.add("(?i)onabort");
		MALICIOUS_STRING_LIST.add("(?i)onactivate");
		MALICIOUS_STRING_LIST.add("(?i)onafterprint");
		MALICIOUS_STRING_LIST.add("(?i)onafterupdate");
		MALICIOUS_STRING_LIST.add("(?i)onbeforeactivate");
		MALICIOUS_STRING_LIST.add("(?i)onbeforecopy");
		MALICIOUS_STRING_LIST.add("(?i)onbeforecut");
		MALICIOUS_STRING_LIST.add("(?i)onbeforedeactivate");
		MALICIOUS_STRING_LIST.add("(?i)onbeforeeditfocus");
		MALICIOUS_STRING_LIST.add("(?i)onbeforepaste");
		MALICIOUS_STRING_LIST.add("(?i)onbeforeprint");
		MALICIOUS_STRING_LIST.add("(?i)onbeforeunload");
		MALICIOUS_STRING_LIST.add("(?i)onbeforeupdate");
		MALICIOUS_STRING_LIST.add("(?i)onblur");
		MALICIOUS_STRING_LIST.add("(?i)onbounce");
		MALICIOUS_STRING_LIST.add("(?i)oncellchange");
		MALICIOUS_STRING_LIST.add("(?i)onchange");
		MALICIOUS_STRING_LIST.add("(?i)onclick");
		MALICIOUS_STRING_LIST.add("(?i)oncontextmenu");
		MALICIOUS_STRING_LIST.add("(?i)oncontrolselect");
		MALICIOUS_STRING_LIST.add("(?i)oncopy");
		MALICIOUS_STRING_LIST.add("(?i)oncut");
		MALICIOUS_STRING_LIST.add("(?i)ondataavailable");
		MALICIOUS_STRING_LIST.add("(?i)ondatasetchanged");
		MALICIOUS_STRING_LIST.add("(?i)ondatasetcomplete");
		MALICIOUS_STRING_LIST.add("(?i)ondblclick");
		MALICIOUS_STRING_LIST.add("(?i)ondeactivate");
		MALICIOUS_STRING_LIST.add("(?i)ondrag");
		MALICIOUS_STRING_LIST.add("(?i)ondragend");
		MALICIOUS_STRING_LIST.add("(?i)ondragenter");
		MALICIOUS_STRING_LIST.add("(?i)ondragleave");
		MALICIOUS_STRING_LIST.add("(?i)ondragover");
		MALICIOUS_STRING_LIST.add("(?i)ondragstart");
		MALICIOUS_STRING_LIST.add("(?i)ondrop");
		MALICIOUS_STRING_LIST.add("(?i)onerror");
		MALICIOUS_STRING_LIST.add("(?i)onerrorupdate");
		MALICIOUS_STRING_LIST.add("(?i)onfilterchange");
		MALICIOUS_STRING_LIST.add("(?i)onfinish");
		MALICIOUS_STRING_LIST.add("(?i)onfocus");
		MALICIOUS_STRING_LIST.add("(?i)onfocusin");
		MALICIOUS_STRING_LIST.add("(?i)onfocusout");
		MALICIOUS_STRING_LIST.add("(?i)onhelp");
		MALICIOUS_STRING_LIST.add("(?i)onkeydown");
		MALICIOUS_STRING_LIST.add("(?i)onkeypress");
		MALICIOUS_STRING_LIST.add("(?i)onkeyup");
		MALICIOUS_STRING_LIST.add("(?i)onlayoutcomplete");
		MALICIOUS_STRING_LIST.add("(?i)onload");
		MALICIOUS_STRING_LIST.add("(?i)onlosecapture");
		MALICIOUS_STRING_LIST.add("(?i)onmousedown");
		MALICIOUS_STRING_LIST.add("(?i)onmouseenter");
		MALICIOUS_STRING_LIST.add("(?i)onmouseleave");
		MALICIOUS_STRING_LIST.add("(?i)onmousemove");
		MALICIOUS_STRING_LIST.add("(?i)onmouseout");
		MALICIOUS_STRING_LIST.add("(?i)onmouseover");
		MALICIOUS_STRING_LIST.add("(?i)onmouseup");
		MALICIOUS_STRING_LIST.add("(?i)onmousewheel");
		MALICIOUS_STRING_LIST.add("(?i)onmove");
		MALICIOUS_STRING_LIST.add("(?i)onmoveend");
		MALICIOUS_STRING_LIST.add("(?i)onmovestart");
		MALICIOUS_STRING_LIST.add("(?i)onpaste");
		MALICIOUS_STRING_LIST.add("(?i)onpropertychange");
		MALICIOUS_STRING_LIST.add("(?i)onreadystatechange");
		MALICIOUS_STRING_LIST.add("(?i)onreset");
		MALICIOUS_STRING_LIST.add("(?i)onresize");
		MALICIOUS_STRING_LIST.add("(?i)onresizeend");
		MALICIOUS_STRING_LIST.add("(?i)onresizestart");
		MALICIOUS_STRING_LIST.add("(?i)onrowenter");
		MALICIOUS_STRING_LIST.add("(?i)onrowexit");
		MALICIOUS_STRING_LIST.add("(?i)onrowsdelete");
		MALICIOUS_STRING_LIST.add("(?i)onrowsinserted");
		MALICIOUS_STRING_LIST.add("(?i)onscroll");
		MALICIOUS_STRING_LIST.add("(?i)onselect");
		MALICIOUS_STRING_LIST.add("(?i)onselectionchange");
		MALICIOUS_STRING_LIST.add("(?i)onselectstart");
		MALICIOUS_STRING_LIST.add("(?i)onstart");
		MALICIOUS_STRING_LIST.add("(?i)onstop");
		MALICIOUS_STRING_LIST.add("(?i)onsubmit");
		MALICIOUS_STRING_LIST.add("(?i)onunload");
	};
	
	public static String filterXSS(String value) {
		if (value != null) {
			for (String maliciousString : MALICIOUS_STRING_LIST) {
				value = value.replaceAll(maliciousString, "");
			}
		}
		return value;
	}
```
