/*
 * The MIT License
 *
 * Copyright 2013 Jesse Glick.
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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionList;
import hudson.ExtensionPoint;
import hudson.security.SecurityRealm;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Listener notified of various significant events related to security.
 * @since 1.548
 */
public abstract class SecurityListener implements ExtensionPoint {

    private static final Logger LOGGER = Logger.getLogger(SecurityListener.class.getName());

    /**
     * Fired when a user was successfully authenticated using credentials. It could be password or any other credentials.
     * This might be via the web UI, or via REST (using API token or Basic), or CLI (remoting, auth, ssh)
     * or any other way plugins can propose.
     * @param details details of the newly authenticated user, such as name and groups.
     * @since 2.266
     */
    protected void authenticated2(@NonNull UserDetails details) {
        authenticated(org.acegisecurity.userdetails.UserDetails.fromSpring(details));
    }

    /**
     * @deprecated use {@link #authenticated2}
     */
    @Deprecated
    protected void authenticated(@NonNull org.acegisecurity.userdetails.UserDetails details) {}

    /**
     * Same event as {@link #authenticated2}, enriched with {@link AuthenticationDetails} (see
     * {@link #ambientDetails()} for where this comes from and what {@code null} means here). Unlike
     * {@code authenticated3} on the {@code prototype/option4-webauthentication-details}/
     * {@code option5-enriched-authentication-details} branches, nothing is threaded through any call
     * argument to get here: {@link #fireAuthenticated2} builds it ambiently instead, so every existing
     * caller, including plugin code that fires it directly and is never touched for this (citations in
     * this class's own test), gets it for free, with zero changes on their end.
     *
     * <p>Default implementation delegates to {@link #authenticated2}, so existing overrides keep working
     * unchanged, same non-breaking pattern used when {@code authenticated2} itself was added.
     *
     * @param details details of the newly authenticated user, same as {@link #authenticated2}.
     * @param authDetails see {@link #ambientDetails()}.
     */
    protected void authenticated3(@NonNull UserDetails details, @CheckForNull AuthenticationDetails authDetails) {
        authenticated2(details);
    }

    /**
     * Fired when a user tried to authenticate but failed.
     * In case the authentication method uses multiple layers to validate the credentials,
     * we do fire this event only when even the last layer failed to authenticate.
     * @param username the user
     * @see #authenticated2
     */
    protected void failedToAuthenticate(@NonNull String username){}

    /**
     * Same mechanism as {@link #authenticated3}.
     * @param authDetails see {@link #ambientDetails()}.
     */
    protected void failedToAuthenticate2(@NonNull String username, @CheckForNull AuthenticationDetails authDetails) {
        failedToAuthenticate(username);
    }

    /**
     * Fired when a user has logged in. Compared to authenticated, there is a notion of storage / cache.
     * Would be called after {@link #authenticated2}.
     * It should be called after the {@link SecurityContextHolder#getContext()}'s authentication is set.
     * @param username the user
     */
    protected void loggedIn(@NonNull String username){}

    /**
     * Same mechanism as {@link #authenticated3}.
     * @param authDetails see {@link #ambientDetails()}.
     */
    protected void loggedIn2(@NonNull String username, @CheckForNull AuthenticationDetails authDetails) {
        loggedIn(username);
    }

    /**
     * @since 2.161
     *
     * Fired after a new user account has been created and saved to disk.
     *
     * @param username the user
     */
    protected void userCreated(@NonNull String username) {}

    /**
     * Fired when a user has failed to log in.
     * Would be called after {@link #failedToAuthenticate}.
     * @param username the user
     */
    protected void failedToLogIn(@NonNull String username){}

    /**
     * Same mechanism as {@link #authenticated3}.
     * @param authDetails see {@link #ambientDetails()}.
     */
    protected void failedToLogIn2(@NonNull String username, @CheckForNull AuthenticationDetails authDetails) {
        failedToLogIn(username);
    }

    /**
     * Fired when a user logs out.
     * @param username the user
     */
    protected void loggedOut(@NonNull String username){}

    /**
     * @since 2.266
     */
    public static void fireAuthenticated2(@NonNull UserDetails details) {
        if (LOGGER.isLoggable(Level.FINE)) {
            List<String> groups = new ArrayList<>();
            for (GrantedAuthority auth : details.getAuthorities()) {
                if (!auth.equals(SecurityRealm.AUTHENTICATED_AUTHORITY2)) {
                    groups.add(auth.getAuthority());
                }
            }
            LOGGER.log(Level.FINE, "authenticated: {0} {1}", new Object[] {details.getUsername(), groups});
        }
        fireEnriched(details, SecurityListener::authenticated3);
    }

    /**
     * Reads whatever {@link RequestContextCaptureFilter} captured on this thread and wraps it, called
     * once per {@code fire*} call by {@link #fireEnriched}, safe to call from a static dispatcher because
     * the capturing {@code Filter}'s own {@code doFilter} call is still synchronously on the stack for
     * every path this fires from (see {@link RequestContextCaptureFilter}'s own Javadoc for the full
     * mechanism).
     *
     * @return {@code null} if called from a thread with no captured request, i.e. the call happened off
     *     the original request's thread.
     */
    @CheckForNull
    private static AuthenticationDetails ambientDetails() {
        HttpServletRequest request = RequestContextCaptureFilter.currentRequest();
        return request == null ? null : new AuthenticationDetails(request);
    }

    /**
     * Shared by every enriched {@code fire*} method, so
     * adding a new one later gets ambient enrichment automatically instead of needing someone to
     * remember to call {@link #ambientDetails()} and loop {@link #all()} by hand.
     */
    private static <T> void fireEnriched(@NonNull T payload, @NonNull EnrichedDispatch<T> dispatch) {
        AuthenticationDetails authDetails = ambientDetails();
        for (SecurityListener l : all()) {
            dispatch.fire(l, payload, authDetails);
        }
    }

    @FunctionalInterface
    private interface EnrichedDispatch<T> {
        void fire(SecurityListener listener, T payload, @CheckForNull AuthenticationDetails authDetails);
    }

    /**
     * @deprecated use {@link #fireAuthenticated2}
     * @since 1.569
     */
    @Deprecated
    public static void fireAuthenticated(@NonNull org.acegisecurity.userdetails.UserDetails details) {
        fireAuthenticated2(details.toSpring());
    }

    /** @since 2.161 */
    public static void fireUserCreated(@NonNull String username) {
        LOGGER.log(Level.FINE, "new user created: {0}", username);
        for (SecurityListener l : all()) {
            l.userCreated(username);
        }
    }

    /** @since 1.569 */
    public static void fireFailedToAuthenticate(@NonNull String username) {
        LOGGER.log(Level.FINE, "failed to authenticate: {0}", username);
        fireEnriched(username, SecurityListener::failedToAuthenticate2);
    }

    /** @since 1.569 */
    public static void fireLoggedIn(@NonNull String username) {
        LOGGER.log(Level.FINE, "logged in: {0}", username);
        fireEnriched(username, SecurityListener::loggedIn2);
    }

    /** @since 1.569 */
    public static void fireFailedToLogIn(@NonNull String username) {
        LOGGER.log(Level.FINE, "failed to log in: {0}", username);
        fireEnriched(username, SecurityListener::failedToLogIn2);
    }

    /** @since 1.569 */
    public static void fireLoggedOut(@NonNull String username) {
        LOGGER.log(Level.FINE, "logged out: {0}", username);
        for (SecurityListener l : all()) {
            l.loggedOut(username);
        }
    }

    private static List<SecurityListener> all() {
        return ExtensionList.lookup(SecurityListener.class);
    }

}
