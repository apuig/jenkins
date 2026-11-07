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
import static org.junit.jupiter.api.Assertions.assertNull;

import hudson.ExtensionList;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Demonstrates Option 5: {@code authenticated3} gets
 * {@link AuthenticationDetails}, a Jenkins-specific superset of Spring's {@code WebAuthenticationDetails}
 * that also carries an explicit header allow-list, for interactive login and real-password Basic auth
 * (both via a swapped {@code AuthenticationDetailsSource}) and API-token Basic auth (built inline, since
 * that path already has the live request). Never carries the {@code Authorization} header, by construction
 * ({@link AuthenticationDetails}'s allow-list doesn't include it).
 *
 * <p>Confirmed NOT realm-independent (see {@code REQUEST_CONTEXT_CONCLUSIONS.md}): oic-auth-plugin,
 * saml-plugin, active-directory-plugin, and ldap-plugin all call {@code SecurityListener.fireAuthenticated2}
 * directly from their own code, bypassing every call site this prototype touches.
 */
@WithJenkins
class Authenticated3EnrichedDetailsTest {

    private static final String MARKER_HEADER = "X-Prototype-Marker";

    private JenkinsRule j;
    private Spy spy;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        spy = ExtensionList.lookupSingleton(SpyImpl.class);
        spy.clear();
    }

    @Test
    void interactiveLoginGetsHeaderAndSessionId() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();
        wc.addRequestHeader(MARKER_HEADER, "session-login-proof");

        wc.login("alice");

        assertEquals(1, spy.captured.size(), "authenticated3 should have fired exactly once");
        AuthenticationDetails details = spy.captured.get(0);
        assertNotNull(details, "authenticated3 should receive a non-null AuthenticationDetails for interactive login");
        assertNotNull(details.getSessionId());
        assertNull(details.getHeaders().get(MARKER_HEADER), "marker isn't on the allow-list, confirms the allow-list is enforced, not just absent by luck");
    }

    @Test
    void realPasswordBasicAuthGetsUserAgentHeader() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();
        wc.withBasicCredentials("bob", "bob");

        wc.goTo("whoAmI/api/json", "application/json");

        assertEquals(1, spy.captured.size(), "authenticated3 should have fired exactly once");
        AuthenticationDetails details = spy.captured.get(0);
        assertNotNull(details, "authenticated3 should receive a non-null AuthenticationDetails for real-password Basic auth");
        assertFalse(details.getHeaders().get("User-Agent") == null || details.getHeaders().get("User-Agent").isEmpty(),
                "User-Agent is on the allow-list and htmlunit always sends one");
    }

    @Test
    void apiTokenBasicAuthGetsUserAgentHeaderToo() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        hudson.model.User carol = hudson.model.User.getById("carol", true);
        ApiTokenProperty prop = carol.getProperty(ApiTokenProperty.class);
        jenkins.security.apitoken.TokenUuidAndPlainValue token = prop.getTokenStore().generateNewToken("test");

        WebClient wc = j.createWebClient().withBasicCredentials("carol", token.plainValue);
        wc.goTo("whoAmI/api/json", "application/json");

        assertEquals(1, spy.captured.size(), "authenticated3 should have fired exactly once");
        AuthenticationDetails details = spy.captured.get(0);
        assertNotNull(details, "authenticated3 should receive a non-null AuthenticationDetails for API-token Basic auth");
        assertFalse(details.getHeaders().get("User-Agent") == null || details.getHeaders().get("User-Agent").isEmpty());
    }

    public abstract static class Spy extends SecurityListener {
        final List<AuthenticationDetails> captured = new ArrayList<>();

        void clear() {
            captured.clear();
        }

        @Override
        protected void authenticated3(UserDetails details, AuthenticationDetails authDetails) {
            captured.add(authDetails);
        }
    }

    @TestExtension
    public static class SpyImpl extends Spy {}
}
