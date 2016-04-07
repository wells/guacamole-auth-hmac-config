package com.brianwells.guacamole.net.hmac;

import java.io.File;
import junit.framework.TestCase;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.environment.LocalEnvironment;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.UserContext;
import org.glyptodon.guacamole.net.auth.simple.SimpleUserContext;
import org.glyptodon.guacamole.properties.GuacamoleProperties;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static com.brianwells.guacamole.net.hmac.HmacAuthenticationProvider.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HmacAuthenticationProviderTest extends TestCase {
    protected static final long ONE_HOUR = 60000L;
    protected static final String connectionId = "test-pc";

    public void setUp() throws Exception {
        super.setUp();
        setGuacamoleProperty("secret-key", "secret");
        setGuacamoleProperty("timestamp-age-limit", String.valueOf(ONE_HOUR));
    }

    public void testSuccess() throws GuacamoleException {
        HttpServletRequest request = getHttpServletRequest();

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        TimeProviderInterface timeProvider = mock(TimeProviderInterface.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L);
        Environment environment = mock(Environment.class);
        when(environment.getGuacamoleHome()).thenReturn(new File("src/test/resources"));
        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(timeProvider, environment);

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNotNull(configs);
        assertEquals(1, configs.size());
        GuacamoleConfiguration config = configs.get(connectionId);
        assertNotNull(config);
        assertEquals("rdp", config.getProtocol());
    }

    public void testHostnameFailure() throws GuacamoleException {
        HttpServletRequest request = mockRequest(new HashMap<String, String>() {{
            put(CONNECTION_PARAM, "other-connection");
            put(TIMESTAMP_PARAM,  "1373563683000");
            // Test signature was generated with the following PHP snippet
            // base64_encode(hash_hmac('sha1', '1373563683000rdp10000001hostname10.2.3.4port3389', 'secret', true));
            put(SIGNATURE_PARAM, "uvPcq+epk1wDfxlM5UOZp3bDJ2Y=");
        }});

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        TimeProviderInterface timeProvider = mock(TimeProviderInterface.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L);
        Environment environment = mock(Environment.class);
        when(environment.getGuacamoleHome()).thenReturn(new File("src/test/resources"));
        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(timeProvider, environment);

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNull(configs);
    }

    public void testTimestampFresh() throws Exception {
        HttpServletRequest request = getHttpServletRequest();

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        TimeProviderInterface timeProvider = mock(TimeProviderInterface.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L + ONE_HOUR - 1l);
        Environment environment = mock(Environment.class);
        when(environment.getGuacamoleHome()).thenReturn(new File("src/test/resources"));
        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(timeProvider, environment);

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNotNull(configs);
        assertEquals(1, configs.size());
        GuacamoleConfiguration config = configs.get(connectionId);
        assertNotNull(config);
    }

    public void testTimestampStale() throws Exception {
        HttpServletRequest request = getHttpServletRequest();

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        TimeProviderInterface timeProvider = mock(TimeProviderInterface.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L + ONE_HOUR);
        Environment environment = mock(Environment.class);
        when(environment.getGuacamoleHome()).thenReturn(new File("src/test/resources"));
        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(timeProvider, environment);

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);
        assertNull(configs);
        
        // test that updateUserContext also returns null when the timestamp is stale
        Map<String, GuacamoleConfiguration> dummyConfigs = new HashMap<String, GuacamoleConfiguration>();
        dummyConfigs.put("dummy", new GuacamoleConfiguration());
        SimpleUserContext context = new SimpleUserContext(authProvider, dummyConfigs);
        HmacAuthenticatedUser user = new HmacAuthenticatedUser(authProvider, credentials, null);
        UserContext updatedUserContext = authProvider.updateUserContext(context, user);
        assertNull(updatedUserContext);
    }

    private HttpServletRequest getHttpServletRequest() {
        return mockRequest(new HashMap<String, String>() {{
            put(CONNECTION_PARAM, connectionId);
            put(TIMESTAMP_PARAM,  "1373563683000");
            // Test signature was generated with the following PHP snippet
            // base64_encode(hash_hmac('sha1', '1373563683000rdp10000001hostname10.2.3.4port3389', 'secret', true));
            put(SIGNATURE_PARAM, "uvPcq+epk1wDfxlM5UOZp3bDJ2Y=");
        }});
    }

    private static HttpServletRequest mockRequest(final Map<String, String> queryParams) {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(anyString())).then(new Answer<Object>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                String key = (String) invocationOnMock.getArguments()[0];
                return queryParams.get(key);
            }
        });

        // Note this is invalidating the servlet API, but I only use the keys so I don't care
        when(request.getParameterMap()).thenReturn(queryParams);

        return request;
    }

    private void setGuacamoleProperty(String propertyName, String propertyValue) throws NoSuchFieldException, IllegalAccessException {
        Field field = GuacamoleProperties.class.getDeclaredField("properties");
        field.setAccessible(true);
        Properties properties =  (Properties) field.get(GuacamoleProperties.class);
        properties.setProperty(propertyName, propertyValue);
    }
}
