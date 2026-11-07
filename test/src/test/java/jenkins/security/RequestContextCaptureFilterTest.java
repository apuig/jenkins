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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import hudson.ExtensionList;
import hudson.model.UnprotectedRootAction;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.ChainedServletFilter2;
import hudson.security.GroupDetails;
import hudson.util.HttpResponses;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.kohsuke.stapler.HttpResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Demonstrates that {@link RequestContextCaptureFilter}
 * lets a {@link SecurityListener} read the real {@link HttpServletRequest} (here, a marker header)
 * from inside {@code authenticated2}/{@code loggedIn}, for both interactive (session) login and
 * Basic-auth login, and that this survives a realm whose {@code createFilter} wraps the default
 * chain additively, the way {@code org.jenkinsci.plugins.oic.OicSecurityRealm} does.
 */
@WithJenkins
class RequestContextCaptureFilterTest {

    private static final String MARKER_HEADER = "X-Prototype-Marker";

    private JenkinsRule j;
    private CapturingSpySecurityListener spy;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        spy = ExtensionList.lookupSingleton(CapturingSpySecurityListenerImpl.class);
        spy.clear();
    }

    @Test
    void interactiveLoginExposesRealRequestToSecurityListener() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();
        wc.addRequestHeader(MARKER_HEADER, "session-login-proof");

        wc.login("alice"); // DummySecurityRealm: username == password

        assertFalse(spy.authenticatedMarkers.isEmpty(), "authenticated2 should have fired");
        assertEquals("session-login-proof", spy.authenticatedMarkers.get(spy.authenticatedMarkers.size() - 1));
        assertFalse(spy.loggedInMarkers.isEmpty(), "loggedIn should have fired");
        assertEquals("session-login-proof", spy.loggedInMarkers.get(spy.loggedInMarkers.size() - 1));
    }

    @Test
    void basicAuthLoginAlsoExposesRealRequestToSecurityListener() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();
        wc.addRequestHeader(MARKER_HEADER, "basic-auth-proof");
        wc.withBasicCredentials("bob", "bob");

        wc.goTo("prototypeProbe", "text/plain");

        assertFalse(spy.authenticatedMarkers.isEmpty(), "authenticated2 should have fired");
        assertEquals("basic-auth-proof", spy.authenticatedMarkers.get(spy.authenticatedMarkers.size() - 1));
    }

    @Test
    void realmThatWrapsDefaultChainLikeOicAuthStillExposesRealRequest() throws Exception {
        j.jenkins.setSecurityRealm(new WrappingSecurityRealm());
        WebClient wc = j.createWebClient();
        wc.addRequestHeader(MARKER_HEADER, "oic-style-wrap-proof");
        wc.withBasicCredentials("carol", "carol");

        wc.goTo("prototypeProbe", "text/plain");

        assertFalse(spy.authenticatedMarkers.isEmpty(), "authenticated2 should have fired");
        assertEquals("oic-style-wrap-proof", spy.authenticatedMarkers.get(spy.authenticatedMarkers.size() - 1));
    }

    /** Self-contained prototype spy, deliberately not reusing the shared {@link SpySecurityListener}. */
    public abstract static class CapturingSpySecurityListener extends SecurityListener {
        final List<String> authenticatedMarkers = new ArrayList<>();
        final List<String> loggedInMarkers = new ArrayList<>();

        void clear() {
            authenticatedMarkers.clear();
            loggedInMarkers.clear();
        }

        @Override
        protected void authenticated2(UserDetails details) {
            authenticatedMarkers.add(captureMarker());
        }

        @Override
        protected void loggedIn(String username) {
            loggedInMarkers.add(captureMarker());
        }

        private static String captureMarker() {
            HttpServletRequest req = RequestContextCaptureFilter.currentRequest();
            return req == null ? null : req.getHeader(MARKER_HEADER);
        }
    }

    @TestExtension
    public static class CapturingSpySecurityListenerImpl extends CapturingSpySecurityListener {}

    @TestExtension
    public static class Probe implements UnprotectedRootAction {
        @Override
        public String getIconFileName() {
            return null;
        }

        @Override
        public String getDisplayName() {
            return null;
        }

        @Override
        public String getUrlName() {
            return "prototypeProbe";
        }

        public HttpResponse doIndex() {
            return HttpResponses.text("ok");
        }
    }

    /**
     * Mirrors, structurally, the real {@code org.jenkinsci.plugins.oic.OicSecurityRealm#createFilter}
     * (oic-auth-plugin, {@code src/main/java/org/jenkinsci/plugins/oic/OicSecurityRealm.java:750-761}):
     * {@code return new ChainedServletFilter2(super.createFilter(filterConfig), new Filter() { ... });}.
     * oic-auth-plugin itself is not a dependency of this module; this is a faithful structural stand-in.
     */
    private static class WrappingSecurityRealm extends AbstractPasswordBasedSecurityRealm {
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
