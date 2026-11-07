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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import hudson.ExtensionList;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.AuthenticationProcessingFilter2;
import hudson.security.ChainedServletFilter2;
import hudson.security.GroupDetails;
import hudson.security.HttpSessionContextIntegrationFilter2;
import hudson.security.SecurityRealm;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterConfig;
import java.util.ArrayList;
import java.util.List;
import jenkins.util.SystemProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

/**
 * Demonstrates {@code option6bis-unconditional-capture-filter}'s headline improvement over {@code option6-ambient-dispatch-enrichment}:
 * {@link RequestContextCaptureFilter} is no longer installed via {@link SecurityRealm#createFilterImpl},
 * so it keeps capturing even for a {@link SecurityRealm} whose own {@link SecurityRealm#createFilter}
 * override never calls {@code super.createFilter()} at all (the non-additive case {@code OicSecurityRealm}
 * avoids today, but nothing stops a different realm from hitting it). {@link NonAdditiveFilterRealm} below
 * hand-assembles the same filters {@link SecurityRealm#createFilterImpl} would, from scratch, without
 * calling {@code super}, to prove the point.
 */
@WithJenkins
class Option6BisUnconditionalCaptureFilterTest {

    private JenkinsRule j;
    private Spy spy;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        spy = ExtensionList.lookupSingleton(SpyImpl.class);
        spy.clear();
    }

    @Test
    void interactiveLoginStillCapturesUnderNonAdditiveRealm() throws Exception {
        j.jenkins.setSecurityRealm(new NonAdditiveFilterRealm());
        WebClient wc = j.createWebClient();

        wc.login("alice"); // NonAdditiveFilterRealm: username == password

        assertEquals(1, spy.authenticatedCaptured.size(), "authenticated3 should have fired exactly once");
        AuthenticationDetails details = spy.authenticatedCaptured.get(0);
        assertNotNull(details, "ambient capture should survive a non-additive createFilter override");
        assertNotNull(details.getSessionId());
        assertFalse(spy.loggedInCaptured.isEmpty(), "loggedIn2 should have fired too, same ambient mechanism");
        assertNotNull(spy.loggedInCaptured.get(0));
    }

    @Test
    void basicAuthStillCapturesUnderNonAdditiveRealm() throws Exception {
        j.jenkins.setSecurityRealm(new NonAdditiveFilterRealm());
        WebClient wc = j.createWebClient();
        wc.withBasicCredentials("bob", "bob");

        wc.goTo("whoAmI/api/json", "application/json");

        assertEquals(1, spy.authenticatedCaptured.size(), "authenticated3 should have fired exactly once");
        AuthenticationDetails details = spy.authenticatedCaptured.get(0);
        assertNotNull(details, "ambient capture should survive a non-additive createFilter override for Basic auth too");
        assertNotNull(details.getHeaders().get("User-Agent"));
    }

    public abstract static class Spy extends SecurityListener {
        final List<AuthenticationDetails> authenticatedCaptured = new ArrayList<>();
        final List<AuthenticationDetails> loggedInCaptured = new ArrayList<>();

        void clear() {
            authenticatedCaptured.clear();
            loggedInCaptured.clear();
        }

        @Override
        protected void authenticated3(UserDetails details, AuthenticationDetails authDetails) {
            authenticatedCaptured.add(authDetails);
        }

        @Override
        protected void loggedIn2(String username, AuthenticationDetails authDetails) {
            loggedInCaptured.add(authDetails);
        }
    }

    @TestExtension
    public static class SpyImpl extends Spy {}

    /**
     * Hand-assembles the exact same filter list {@link SecurityRealm#createFilterImpl} builds, without
     * ever calling {@code super.createFilter()}/{@code createFilterImpl()} — the non-additive case. Under
     * {@code option6-ambient-dispatch-enrichment}, a realm like this would never install
     * {@link RequestContextCaptureFilter} at all, so {@code authDetails} would be {@code null} throughout.
     * Under {@code option6bis-unconditional-capture-filter}, the filter is registered independently in {@code web-fragment.xml}, so it's
     * unaffected by anything this method does or doesn't call.
     */
    private static class NonAdditiveFilterRealm extends AbstractPasswordBasedSecurityRealm {
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
            SecurityComponents sc = getSecurityComponents();
            List<Filter> filters = new ArrayList<>();
            {
                HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
                repo.setAllowSessionCreation(false);
                filters.add(new HttpSessionContextIntegrationFilter2(repo));
            }
            {
                BasicHeaderProcessor bhp = new BasicHeaderProcessor();
                BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
                entryPoint.setRealmName("Jenkins");
                bhp.setAuthenticationEntryPoint(entryPoint);
                filters.add(bhp);
            }
            {
                AuthenticationProcessingFilter2 apf = new AuthenticationProcessingFilter2(getAuthenticationGatewayUrl());
                apf.setAuthenticationManager(sc.manager2);
                if (SystemProperties.getInteger(SecurityRealm.class.getName() + ".sessionFixationProtectionMode", 1) == 1) {
                    apf.setSessionAuthenticationStrategy(new SessionFixationProtectionStrategy());
                }
                apf.setRememberMeServices(sc.rememberMe2);
                AuthenticationSuccessHandler successHandler = new AuthenticationSuccessHandler();
                successHandler.setTargetUrlParameter("from");
                apf.setAuthenticationSuccessHandler(successHandler);
                apf.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/loginError"));
                filters.add(apf);
            }
            RememberMeAuthenticationFilter rememberMe = new RememberMeAuthenticationFilter(sc.manager2, sc.rememberMe2);
            rememberMe.setSessionAuthenticationStrategy(new SessionFixationProtectionStrategy());
            filters.add(rememberMe);
            filters.addAll(commonFilters());
            return new ChainedServletFilter2(filters); // never calls super.createFilter()
        }
    }
}
