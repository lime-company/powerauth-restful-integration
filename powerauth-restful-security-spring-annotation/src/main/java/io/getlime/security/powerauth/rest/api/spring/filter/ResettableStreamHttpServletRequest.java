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
package io.getlime.security.powerauth.rest.api.spring.filter;

import com.google.common.io.ByteStreams;

import javax.annotation.Nonnull;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.util.Arrays;

/**
 * Resettable HTTP servlet request stream.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class ResettableStreamHttpServletRequest extends HttpServletRequestWrapper {

    private byte[] requestBody = new byte[0];
    private boolean bufferFilled = false;

    /**
     * Constructs a request object wrapping the given request.
     *
     * @param request The request to wrap
     * @throws IllegalArgumentException if the request is null
     */
    public ResettableStreamHttpServletRequest(HttpServletRequest request) {
        super(request);
    }

    /**
     * Get request body.
     * @return Bytes with the request body contents.
     * @throws IOException In case stream reading fails.
     */
    public byte[] getRequestBody() throws IOException {

        if (bufferFilled) {
            return Arrays.copyOf(requestBody, requestBody.length);
        }

        InputStream inputStream = super.getInputStream();

        //TODO: Replace by Java 9 InputStream.readAllBytes() method when relevant.
        requestBody = ByteStreams.toByteArray(inputStream);

        bufferFilled = true;

        return requestBody;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return new CustomServletInputStream(getRequestBody());
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }

    private static class CustomServletInputStream extends ServletInputStream {

        private final ByteArrayInputStream buffer;

        public CustomServletInputStream(byte[] contents) {
            this.buffer = new ByteArrayInputStream(contents);
        }

        @Override
        public int read(@Nonnull byte[] b, int off, int len) {
            return buffer.read(b, off, len);
        }

        @Override
        public int readLine(byte[] b, int off, int len) {
            // Copy-paste from ServletInputStream code, just replaced 'this' with 'buffer'.
            if(len <= 0) {
                return 0;
            } else {
                int count = 0;
                int c;
                while((c = buffer.read()) != -1) {
                    b[off++] = (byte)c;
                    ++count;
                    if(c == '\n' || count == len) {
                        break;
                    }
                }
                return count > 0?count:-1;
            }
        }

        @Override
        public int read() {
            return buffer.read();
        }

        @Override
        public int read(@Nonnull byte[] b) throws IOException {
            return buffer.read(b);
        }

        @Override
        public boolean isFinished() {
            return buffer.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener arg0) {
            throw new RuntimeException("Not implemented");
        }

    }

}