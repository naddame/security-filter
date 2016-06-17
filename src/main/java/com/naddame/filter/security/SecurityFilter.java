package com.naddame.filter.security;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This filtre act as security wall
 *
 *  To use this in spring boot
 *  <code>
 *     @Bean
 *     public FilterRegistrationBean filterRegistrationBean() {
 *       FilterRegistrationBean registrationBean = new FilterRegistrationBean();
 *       SecurityFilter securityFilter = new SecurityFilter();
 *       securityFilter.setEncoding("UTF-8");
 *       securityFilter.setAuthUrl(url);
 *       securityFilter.setAuthTokenName(authtoken);
 *       registrationBean.setFilter(securityFilter);
 *       return registrationBean;
 *      }
 *  </code>
 *   in Web.xml
 *   <code>
 *      <filter>
 *          <filter-name>SecurityFilter</filter-name>
 *          <filter-class>com.naddame.filter.security.SecurityFilter</filter-class>
 *          <init-param>
 *               <param-name>authUrl</param-name>
 *               <param-value>http://server/api/checkLogin</param-value>
 *          </init-param>
 *          <init-param>
 *              <param-name>authTokenName</param-name>
 *              <param-value>Auth-Token</param-value>
 *          </init-param>
 *      </filter>
 *      </code>
 *
 * @author djamel Hamas
 */
public class SecurityFilter implements Filter {

	private Logger log = Logger.getLogger(SecurityFilter.class.getName());

	private final String USER_AGENT = "Mozilla/5.0";

	private String authUrl = null;
	private String authTokenName = null;

	public void destroy() {
		// TODO Auto-generated method stub

	}
	public void init(FilterConfig filterConfig) throws ServletException {
		String p = filterConfig.getInitParameter("authUrl");
		if (null != p) authUrl = p;
		else throw new RuntimeException("The param authUrl is required for the filter");

		p = filterConfig.getInitParameter("authTokenName");
		if (null != p) authTokenName = p;
		else throw new RuntimeException("The param authTokenName is required for the filter");

	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;

		String authToken = req.getHeader(authTokenName);
		String userName = getUserNameFromToken(authToken);

		if (null == userName || userName.length() == 0) {
			forbidden(res, authToken);
			return;
		}
		sendGet(req, res, authToken);

		chain.doFilter(request, response);
	}

	// HTTP GET request
	private void sendGet(HttpServletRequest req, HttpServletResponse res, String token)throws IOException, ServletException {

		URL obj = new URL(authUrl);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("GET");

		//add request header
		con.setRequestProperty("User-Agent", USER_AGENT);
		con.setRequestProperty(authTokenName, token);
		forwardCookies(req, con);

		int responseCode = con.getResponseCode();
		log.log(Level.FINE,"\nSending 'GET' request to URL : " + authUrl);
		log.log(Level.FINE,"Response Code : " + responseCode);

		if (responseCode != 200) {
			forbidden(res, token);
			return;
		}

		/*BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();


        //print result
        System.out.println(response.toString());*/

	}


	private void forbidden(HttpServletResponse res, String token) throws IOException {
		log.log(Level.SEVERE, "authentication error with the token :"+token);
		res.addHeader("Content-Type", "application/json; charset=utf-8");
		res.setStatus(HttpServletResponse.SC_FORBIDDEN);
		OutputStream os = res.getOutputStream();
		if (null == os) System.out.println("os is null");
		String message = "{\"status\":403, \"message\":\"Unauthorized: Authentication token was either missing or invalid.\"}";
		os.write(message.getBytes());
	}

	public static String getUserNameFromToken(String authToken) {

		if (null == authToken) {
			return null;
		}

		String[] parts = authToken.split(":");
		return parts[0];
	}

	private void forwardCookies(HttpServletRequest request,  HttpURLConnection connection) {

		StringBuilder sb = new StringBuilder();
		Cookie[] cookies = request.getCookies();
		cookies = cookies == null ? new Cookie[0] : cookies;
		for(Cookie cookie : cookies) {
			String cookieName = cookie.getName();
			String cookieValue = cookie.getValue();
			sb.append(cookieName);
			sb.append("=");
			sb.append(cookieValue);
			sb.append(";");
		}

		if (sb.length() > 0) {
			connection.setRequestProperty("Cookie", sb.toString());
		}
	}

	public void setAuthUrl(String authUrl) {
		this.authUrl = authUrl;
	}

	public void setAuthTokenName(String authTokenName) {
		this.authTokenName = authTokenName;
	}
}
