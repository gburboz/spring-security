/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.providers.ldap.authenticator;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;


/**
 * Tests {@link LdapShaPasswordEncoder}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapShaPasswordEncoderTests {
    //~ Instance fields ================================================================================================

    LdapShaPasswordEncoder sha;

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        sha = new LdapShaPasswordEncoder();
    }

    @Test
    public void invalidPasswordFails() {
        assertFalse(sha.isPasswordValid("{SHA}ddSFGmjXYPbZC+NXR2kCzBRjqiE=", "wrongpassword", null));
    }

    @Test    
    public void invalidSaltedPasswordFails() {
        assertFalse(sha.isPasswordValid("{SSHA}25ro4PKC8jhQZ26jVsozhX/xaP0suHgX", "wrongpassword", null));
        assertFalse(sha.isPasswordValid("{SSHA}PQy2j+6n5ytA+YlAKkM8Fh4p6u2JxfVd", "wrongpassword", null));
    }

    @Test(expected=IllegalArgumentException.class)
    public void nonByteArraySaltThrowsException() {
        sha.encodePassword("password", "AStringNotAByteArray");
    }

    /**
     * Test values generated by 'slappasswd -h {SHA} -s boabspasswurd'
     */
    @Test
    public void validPasswordSucceeds() {
        sha.setForceLowerCasePrefix(false);
        assertTrue(sha.isPasswordValid("{SHA}ddSFGmjXYPbZC+NXR2kCzBRjqiE=", "boabspasswurd", null));
        assertTrue(sha.isPasswordValid("{sha}ddSFGmjXYPbZC+NXR2kCzBRjqiE=", "boabspasswurd", null));
        sha.setForceLowerCasePrefix(true);
        assertTrue(sha.isPasswordValid("{SHA}ddSFGmjXYPbZC+NXR2kCzBRjqiE=", "boabspasswurd", null));
        assertTrue(sha.isPasswordValid("{sha}ddSFGmjXYPbZC+NXR2kCzBRjqiE=", "boabspasswurd", null));
    }

    /**
     * Test values generated by 'slappasswd -s boabspasswurd'
     */
    @Test
    public void validSaltedPasswordSucceeds() {
        sha.setForceLowerCasePrefix(false);
        assertTrue(sha.isPasswordValid("{SSHA}25ro4PKC8jhQZ26jVsozhX/xaP0suHgX", "boabspasswurd", null));
        assertTrue(sha.isPasswordValid("{ssha}PQy2j+6n5ytA+YlAKkM8Fh4p6u2JxfVd", "boabspasswurd", null));
        sha.setForceLowerCasePrefix(true);
        assertTrue(sha.isPasswordValid("{SSHA}25ro4PKC8jhQZ26jVsozhX/xaP0suHgX", "boabspasswurd", null));
        assertTrue(sha.isPasswordValid("{ssha}PQy2j+6n5ytA+YlAKkM8Fh4p6u2JxfVd", "boabspasswurd", null));
    }

    @Test
    public void correctPrefixCaseIsUsed() {
        sha.setForceLowerCasePrefix(false);
        assertEquals("{SHA}ddSFGmjXYPbZC+NXR2kCzBRjqiE=", sha.encodePassword("boabspasswurd", null));
        assertTrue(sha.encodePassword("somepassword", "salt".getBytes()).startsWith("{SSHA}"));

        sha.setForceLowerCasePrefix(true);
        assertEquals("{sha}ddSFGmjXYPbZC+NXR2kCzBRjqiE=", sha.encodePassword("boabspasswurd", null));
        assertTrue(sha.encodePassword("somepassword", "salt".getBytes()).startsWith("{ssha}"));

    }

    @Test(expected=IllegalArgumentException.class)
    public void invalidPrefixIsRejected() {
    	sha.isPasswordValid("{MD9}xxxxxxxxxx" , "somepassword", null);
    }
    
    @Test(expected=IllegalArgumentException.class)
    public void malformedPrefixIsRejected() {
    	// No right brace
    	sha.isPasswordValid("{SSHA25ro4PKC8jhQZ26jVsozhX/xaP0suHgX" , "somepassword", null);
    }
}
