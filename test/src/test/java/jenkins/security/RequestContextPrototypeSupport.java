/*
 * The MIT License
 *
 * Copyright 2026 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package jenkins.security;

import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.ChainedServletFilter2;
import hudson.security.GroupDetails;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * PROTOTYPE, not a finished core contribution. Shared, mechanism-agnostic test fixtures reused across
 * the several {@code prototype/*} branches investigating how to enhance {@link SecurityListener} with
 * request context (headers, remote address, session id). Lives on {@code prototype/request-context-base};
 * every other prototype branch in this series branches from here instead of {@code master} directly, so
 * the realm-wrapping fixture below (the one piece of scaffolding that's genuinely identical regardless
 * of which mechanism a given branch prototypes) isn't duplicated or allowed to drift across branches.
 *
 * <p>Deliberately NOT shared here: any {@code SecurityListener} spy or probe {@code UnprotectedRootAction}.
 * Those differ per mechanism (what they read, and from where) and {@code @TestExtension} scoping ties
 * them to the concrete test class anyway, so each branch keeps its own, small and mechanism-coupled.
 */
public final class RequestContextPrototypeSupport {

    public static final String MARKER_HEADER = "X-Prototype-Marker";

    private RequestContextPrototypeSupport() {}

    /**
     * Mirrors, structurally, the real {@code org.jenkinsci.plugins.oic.OicSecurityRealm#createFilter}
     * (oic-auth-plugin, {@code src/main/java/org/jenkinsci/plugins/oic/OicSecurityRealm.java:750-761}),
     * confirmed locally in {@code ~/cb/aux/oic-auth-plugin} at commit {@code 8a8b74c97cd4b826e7427706c0ce390076680053}:
     * {@code return new ChainedServletFilter2(super.createFilter(filterConfig), new Filter() { ... });}.
     * oic-auth-plugin itself is not a dependency of this module; this is a faithful structural stand-in,
     * used by every prototype branch to confirm a given mechanism survives a realm that wraps the default
     * filter chain additively instead of relying on it as-is.
     */
    public static class WrappingSecurityRealm extends AbstractPasswordBasedSecurityRealm {
        @Override
        protected UserDetails authenticate2(String username, String password) {
            if (username.equals(password)) {
                return loadUserByUsername2(username);
            }
            throw new BadCredentialsException(username);
        }

        @Override
        public UserDetails loadUserByUsername2(String username) {
            return new User(
                    username, "", true, true, true, true, List.of((GrantedAuthority)
                            new SimpleGrantedAuthority("authenticated")));
        }

        @Override
        public GroupDetails loadGroupByGroupname2(String groupname, boolean fetchMembers) {
            throw new UsernameNotFoundException(groupname);
        }

        @Override
        public Filter createFilter(FilterConfig filterConfig) {
            return new ChainedServletFilter2(super.createFilter(filterConfig), new Filter() {
                @Override
                public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                        throws IOException, ServletException {
                    chain.doFilter(req, res); // stand-in for OicSecurityRealm's own extra filter
                }
            });
        }
    }
}
