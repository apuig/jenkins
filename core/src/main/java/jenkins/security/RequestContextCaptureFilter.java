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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Installed via its own fixed {@code <filter>}/{@code <filter-mapping>} entry in
 * {@code web-fragment.xml}, ordered ahead of {@code authentication-filter}
 * ({@link hudson.security.HudsonFilter}). Because the servlet container dispatches through that
 * list via plain, synchronous, nested calls, any {@link SecurityListener} callback firing deeper
 * in that same call stack, during either interactive form login or Basic/API-token authentication,
 * runs while this filter's own {@link #doFilter} call is still on the stack. A cooperating
 * {@code SecurityListener} implementation can therefore call {@link #currentRequest()} from inside
 * its own callback and get the real, live {@link HttpServletRequest}.
 *
 * <p>Neither {@code Stapler.getCurrentRequest2()} nor a plugin-registered {@code Filter} (added via
 * {@code PluginServletFilter}/{@code HttpServletFilter}) can do this for an interactive login: those
 * run strictly after authentication, and for interactive login specifically, after a short-circuit
 * that means they never run at all for that request.
 *
 * <p>Unlike routing this through {@link SecurityRealm#createFilterImpl}, this filter's own
 * {@code web-fragment.xml} entry runs unconditionally, for every configured {@link SecurityRealm},
 * regardless of whether that realm's {@code createFilter} override is additive: there is no realm
 * that can prevent this filter from installing.
 */
@Restricted(NoExternalUse.class)
public class RequestContextCaptureFilter implements Filter {

    private static final ThreadLocal<HttpServletRequest> CURRENT_REQUEST = new ThreadLocal<>();

    /**
     * @return the request currently flowing through this filter on the calling thread, or null
     *     if called from a thread that isn't inside this filter's {@link #doFilter}.
     */
    @CheckForNull
    public static HttpServletRequest currentRequest() {
        return CURRENT_REQUEST.get();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        boolean http = request instanceof HttpServletRequest;
        // Save/restore rather than set/remove: the same idiom Stapler itself uses for ambient
        // current-request access (org.kohsuke.stapler.Stapler#invoke), so a re-entrant doFilter on
        // the same thread (a forward/include re-entering the chain) restores the outer call's own
        // request instead of leaving it cleared once the inner call's finally runs.
        HttpServletRequest previous = http ? CURRENT_REQUEST.get() : null;
        if (http) {
            CURRENT_REQUEST.set((HttpServletRequest) request);
        }
        try {
            chain.doFilter(request, response);
        } finally {
            if (http) {
                CURRENT_REQUEST.set(previous);
            }
        }
    }
}
