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
import edu.umd.cs.findbugs.annotations.NonNull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Immutable snapshot of the request-derived context available at the moment {@link SecurityListener}
 * fires, built once from the live {@link HttpServletRequest} and never holding a reference to it:
 * containers are free to recycle or invalidate the request object once the response is committed, so
 * nothing here keeps it alive past that point.
 *
 * <p>Carries strictly more than Spring Security's own {@code WebAuthenticationDetails} (remote address,
 * session id), adding an explicit, small allow-list of headers. Deliberately excludes {@code Authorization}:
 * it is the base64-encoded credential for Basic auth, and this type is designed to be logged.
 *
 * <p>Same type used on {@code prototype/option5-enriched-authentication-details}; copied rather than
 * shared across branches that otherwise don't share history.
 *
 * <p><strong>{@code X-Forwarded-For} is client-supplied and not independently verified by this class.</strong>
 * Unless something upstream (a trusted reverse proxy that overwrites rather than appends, or a Jenkins-side
 * trusted-proxy allow-list, neither of which this prototype adds) strips or rewrites it, any client can set
 * this header to an arbitrary value, which this type would then carry into whatever consumes it, including
 * an audit log. Flagged here rather than silently fixed, since the fix is a trusted-proxy policy decision,
 * not something this class can decide on its own; a real core contribution would need to resolve this before
 * treating this field as attributable.
 */
public final class AuthenticationDetails implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final List<String> ALLOWED_HEADERS = List.of("User-Agent", "X-Forwarded-For");

    private final String remoteAddress;
    private final String sessionId;
    private final Map<String, String> headers;

    public AuthenticationDetails(@NonNull HttpServletRequest request) {
        this.remoteAddress = request.getRemoteAddr();
        HttpSession session = request.getSession(false);
        this.sessionId = session == null ? null : session.getId();
        Map<String, String> h = new LinkedHashMap<>();
        for (String name : ALLOWED_HEADERS) {
            String value = request.getHeader(name);
            if (value != null) {
                h.put(name, value);
            }
        }
        this.headers = Collections.unmodifiableMap(h);
    }

    @NonNull
    public String getRemoteAddress() {
        return remoteAddress;
    }

    @CheckForNull
    public String getSessionId() {
        return sessionId;
    }

    /**
     * @return an unmodifiable map of the allow-listed headers present on the request. Never contains
     *     {@code Authorization}, regardless of what the request actually sent.
     */
    @NonNull
    public Map<String, String> getHeaders() {
        return headers;
    }
}
