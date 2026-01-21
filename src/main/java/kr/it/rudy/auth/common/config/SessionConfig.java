package kr.it.rudy.auth.common.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
@EnableRedisHttpSession
public class SessionConfig {

    @Value("${session.cookie.domain:}")
    private String cookieDomain;

    @Value("${session.cookie.same-site:Lax}")
    private String sameSite;

    @Value("${session.cookie.secure:false}")
    private boolean secure;

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("SESSION");
        serializer.setCookiePath("/");

        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            serializer.setDomainName(cookieDomain);
        }

        serializer.setSameSite(sameSite);
        serializer.setUseSecureCookie(secure);

        return serializer;
    }
}
