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
import hudson.model.UnprotectedRootAction;
import hudson.util.HttpResponses;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Demonstrates Option 6: {@code authenticated3}/{@code loggedIn2}
 * get {@link AuthenticationDetails} built ambiently inside {@link SecurityListener}'s own static {@code fire*}
 * dispatchers, reading {@link RequestContextCaptureFilter}'s {@code ThreadLocal}. Unlike
 * {@code prototype/option4-webauthentication-details}/{@code option5-enriched-authentication-details}, this
 * core diff touches only {@code SecurityListener.java} plus one new type; {@code AbstractPasswordBasedSecurityRealm},
 * {@code BasicHeaderRealPasswordAuthenticator}, and {@code BasicHeaderApiTokenAuthenticator} are untouched,
 * same as on master. The headline test below ({@link #directFireFromArbitraryCodeStillGetsEnrichment}) proves
 * that matters: it fires the unmodified {@code SecurityListener.fireAuthenticated2}/{@code fireLoggedIn} calls
 * directly, from code that isn't even a {@code SecurityRealm}, the same way oic-auth-plugin, saml-plugin,
 * active-directory-plugin, and ldap-plugin each do from their own code (file/line citations in
 * {@code tests/audit-ingestion/BEE-75839-securitylistener-and-request-context.md}, section 3, limitation 7,
 * in the unified-release repo), and still gets the enrichment.
 */
@WithJenkins
class Option6AmbientEnrichmentTest {

    private static final String MARKER_HEADER = "User-Agent"; // on the allow-list; htmlunit always sends one

    private JenkinsRule j;
    private Spy spy;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        spy = ExtensionList.lookupSingleton(SpyImpl.class);
        spy.clear();
    }

    @Test
    void interactiveLoginGetsEnrichedDetails() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();

        wc.login("alice");

        assertEquals(1, spy.authenticatedCaptured.size(), "authenticated3 should have fired exactly once");
        AuthenticationDetails details = spy.authenticatedCaptured.get(0);
        assertNotNull(details, "ambient capture should be populated for interactive login");
        assertNotNull(details.getSessionId());
        assertFalse(spy.loggedInCaptured.isEmpty(), "loggedIn2 should have fired too, same ambient mechanism");
        assertNotNull(spy.loggedInCaptured.get(0), "loggedIn2's ambient details should also be populated");
    }

    @Test
    void realPasswordBasicAuthGetsEnrichedDetailsWithNoCodeChangesToThatPath() throws Exception {
        // Exercises BasicHeaderRealPasswordAuthenticator -> manager2.authenticate -> AbstractPasswordBasedSecurityRealm
        // .retrieveUser -> doAuthenticate -> fireAuthenticated2, none of which this prototype modifies.
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();
        wc.withBasicCredentials("bob", "bob");

        wc.goTo("whoAmI/api/json", "application/json");

        assertEquals(1, spy.authenticatedCaptured.size(), "authenticated3 should have fired exactly once");
        AuthenticationDetails details = spy.authenticatedCaptured.get(0);
        assertNotNull(details, "ambient capture should be populated for real-password Basic auth too, with zero changes to that call path");
        assertNotNull(details.getHeaders().get(MARKER_HEADER));
    }

    @Test
    void directFireFromArbitraryCodeStillGetsEnrichment() throws Exception {
        // No SecurityRealm involved at all; see the class Javadoc for which real plugins this simulates.
        // Calls SecurityListener.fireAuthenticated2/fireLoggedIn directly with their UNCHANGED signatures,
        // not through any of the 3 call sites Option 4/5 had to modify. Zero changes needed on the caller's side.
        // A realm must be set so the request flows through SecurityRealm.createFilterImpl() (and therefore
        // RequestContextCaptureFilter); JenkinsRule's default realm (NO_AUTHENTICATION) overrides createFilter()
        // non-additively and skips it entirely, same as any real realm doing that would (RequestContextCaptureFilter's
        // own Javadoc has the full explanation).
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();
        wc.addRequestHeader("X-Forwarded-For", "203.0.113.7");

        wc.goTo("directFireProbe?user=dave", "text/plain");

        assertEquals(1, spy.authenticatedCaptured.size(), "authenticated3 should have fired exactly once, via the ambient dispatcher, for a direct, unchanged fireAuthenticated2 call");
        AuthenticationDetails details = spy.authenticatedCaptured.get(0);
        assertNotNull(details, "ambient capture should be populated even though DirectFireProbe never built or passed any details object itself");
        assertEquals("203.0.113.7", details.getHeaders().get("X-Forwarded-For"));
        assertFalse(spy.loggedInCaptured.isEmpty());
        assertNotNull(spy.loggedInCaptured.get(0));
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
     * Stand-in for a plugin realm's own direct-fire code (e.g. {@code OicSecurityRealm#onSuccess}),
     * deliberately NOT a {@link hudson.security.SecurityRealm} at all: the point is that this mechanism
     * doesn't care who calls {@code fireAuthenticated2}/{@code fireLoggedIn}, or from where.
     */
    @TestExtension
    public static class DirectFireProbe implements UnprotectedRootAction {
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
            return "directFireProbe";
        }

        public HttpResponse doIndex(@QueryParameter String user) {
            UserDetails userDetails = new User(
                    user, "", true, true, true, true, List.of((GrantedAuthority) new SimpleGrantedAuthority("authenticated")));
            SecurityListener.fireAuthenticated2(userDetails); // unchanged signature, see class Javadoc
            SecurityListener.fireLoggedIn(user); // unchanged signature
            return HttpResponses.text("ok");
        }
    }
}
