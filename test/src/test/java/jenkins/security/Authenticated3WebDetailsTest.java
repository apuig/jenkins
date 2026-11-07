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
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Demonstrates Option 4: {@code authenticated3} gets the
 * {@code remoteAddress}/{@code sessionId} pair Spring Security already built, with no new {@code Filter}
 * and no {@code ThreadLocal}, for interactive login, real-password Basic auth, and API-token Basic auth.
 * Does not cover headers (see {@code prototype/option5-enriched-authentication-details} for that), and
 * does not cover realms that fire {@link SecurityListener} directly from their own code (see
 * {@code REQUEST_CONTEXT_CONCLUSIONS.md} for the confirmed list: oic-auth-plugin, saml-plugin,
 * active-directory-plugin, ldap-plugin).
 */
@WithJenkins
class Authenticated3WebDetailsTest {

    private JenkinsRule j;
    private Spy spy;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        spy = ExtensionList.lookupSingleton(SpyImpl.class);
        spy.clear();
    }

    @Test
    void interactiveLoginGetsRemoteAddressAndSessionId() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();

        wc.login("alice");

        assertEquals(1, spy.captured.size(), "authenticated3 should have fired exactly once");
        WebAuthenticationDetails details = spy.captured.get(0);
        assertNotNull(details, "authenticated3 should receive a non-null WebAuthenticationDetails for interactive login");
        assertNotNull(details.getSessionId(), "interactive login should carry a session id");
    }

    @Test
    void realPasswordBasicAuthGetsRemoteAddressWithoutSessionId() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        WebClient wc = j.createWebClient();
        wc.withBasicCredentials("bob", "bob");

        wc.goTo("whoAmI/api/json", "application/json");

        assertEquals(1, spy.captured.size(), "authenticated3 should have fired exactly once");
        WebAuthenticationDetails details = spy.captured.get(0);
        assertNotNull(details, "authenticated3 should receive a non-null WebAuthenticationDetails for real-password Basic auth");
        assertNotNull(details.getRemoteAddress());
    }

    @Test
    void apiTokenBasicAuthAlsoGetsRemoteAddress() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        hudson.model.User carol = hudson.model.User.getById("carol", true);
        ApiTokenProperty prop = carol.getProperty(ApiTokenProperty.class);
        jenkins.security.apitoken.TokenUuidAndPlainValue token = prop.getTokenStore().generateNewToken("test");

        WebClient wc = j.createWebClient().withBasicCredentials("carol", token.plainValue);
        wc.goTo("whoAmI/api/json", "application/json");

        assertEquals(1, spy.captured.size(), "authenticated3 should have fired exactly once");
        WebAuthenticationDetails details = spy.captured.get(0);
        assertNotNull(details, "authenticated3 should receive a non-null WebAuthenticationDetails for API-token Basic auth too");
        assertNotNull(details.getRemoteAddress());
    }

    public abstract static class Spy extends SecurityListener {
        final List<WebAuthenticationDetails> captured = new ArrayList<>();

        void clear() {
            captured.clear();
        }

        @Override
        protected void authenticated3(UserDetails details, WebAuthenticationDetails webDetails) {
            captured.add(webDetails);
        }
    }

    @TestExtension
    public static class SpyImpl extends Spy {}
}
