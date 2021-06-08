/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.getlime.security.powerauth.rest.api.spring.model;

/**
 * Class representing HTTP request body.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthRequestBody {

    private final byte[] requestBytes;

    /**
     * Default constructor for empty HTTP request body.
     */
    public PowerAuthRequestBody() {
        this.requestBytes = new byte[0];
    }

    /**
     * Constructor with HTTP request body bytes.
     * @param requestBytes HTTP request body bytes.
     */
    public PowerAuthRequestBody(byte[] requestBytes) {
        this.requestBytes = requestBytes;
    }

    /**
     * Get HTTP request body bytes.
     * @return HTTP request body bytes.
     */
    public byte[] getRequestBytes() {
        return requestBytes;
    }
}
