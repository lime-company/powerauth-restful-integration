package io.getlime.security.powerauth.rest.api.spring.model;

/**
 * Class defining request objects stored in HTTP servlet request.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthRequestObjects {

    /**
     * Constant for the request attribute name "X-PowerAuth-Request-Body".
     */
    public static final String REQUEST_BODY = "X-PowerAuth-Request-Body";

    /**
     * Constant for the request attribute name "X-PowerAuth-Authentication-Object".
     */
    public static final String AUTHENTICATION_OBJECT = "X-PowerAuth-Authentication-Object";

    /**
     * Constant for the request attribute name "X-PowerAuth-Encryption-Object".
     */
    public static final String ENCRYPTION_OBJECT = "X-PowerAuth-Encryption-Object";

}
