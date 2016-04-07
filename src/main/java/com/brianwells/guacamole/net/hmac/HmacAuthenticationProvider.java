package com.brianwells.guacamole.net.hmac;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.environment.LocalEnvironment;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.UserContext;
import org.glyptodon.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.glyptodon.guacamole.net.auth.simple.SimpleUserContext;
import org.glyptodon.guacamole.properties.GuacamoleProperties;
import org.glyptodon.guacamole.properties.IntegerGuacamoleProperty;
import org.glyptodon.guacamole.properties.StringGuacamoleProperty;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.helpers.XMLReaderFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

public class HmacAuthenticationProvider extends SimpleAuthenticationProvider {

    public static final long TEN_MINUTES = 10 * 60 * 1000;

    // Properties file params
    private static final StringGuacamoleProperty HMAC_SERVER_ID = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "hmac-server-id"; }
    };

    private static final StringGuacamoleProperty SECRET_KEY = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "secret-key"; }
    };

    private static final IntegerGuacamoleProperty TIMESTAMP_AGE_LIMIT = new IntegerGuacamoleProperty() {
        @Override
        public String getName() { return "timestamp-age-limit"; }
    };

    /**
     * Guacamole server environment.
     */
    private final Environment environment;

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(HmacAuthenticationProvider.class);

    // These will be overridden by properties file if present
    private long timestampAgeLimit = TEN_MINUTES; // 10 minutes

    // Per-request parameters
    public static final String SIGNATURE_PARAM = "signature";
    public static final String CONNECTION_PARAM = "connection";
    public static final String TIMESTAMP_PARAM = "timestamp";

    /**
     * The default filename to use for the configuration, if not defined within
     * guacamole.properties.
     */
    public static final String DEFAULT_HMAC_CONFIG = "hmac-config.xml";

    private static final List<String> SIGNED_PARAMETERS = new ArrayList<String>() {{
        add("hostname");
        add("port");
    }};

    private SignatureVerifier signatureVerifier;

    private final TimeProviderInterface timeProvider;

    public HmacAuthenticationProvider(TimeProviderInterface timeProvider, Environment environment) throws GuacamoleException {
        this.timeProvider = timeProvider;
        this.environment = environment;

        String secretKey = GuacamoleProperties.getRequiredProperty(SECRET_KEY);
        signatureVerifier = new SignatureVerifier(secretKey);

        if (GuacamoleProperties.getProperty(TIMESTAMP_AGE_LIMIT) == null){
           timestampAgeLimit = TEN_MINUTES;
        }  else {
           timestampAgeLimit = GuacamoleProperties.getProperty(TIMESTAMP_AGE_LIMIT);
        }
    }

    public HmacAuthenticationProvider() throws GuacamoleException {
        timeProvider = new DefaultTimeProvider();
        environment = new LocalEnvironment();

        String secretKey = GuacamoleProperties.getRequiredProperty(SECRET_KEY);
        signatureVerifier = new SignatureVerifier(secretKey);

        if (GuacamoleProperties.getProperty(TIMESTAMP_AGE_LIMIT) == null){
           timestampAgeLimit = TEN_MINUTES;
        }  else {
           timestampAgeLimit = GuacamoleProperties.getProperty(TIMESTAMP_AGE_LIMIT);
        }
    }

    /**
     * Check if the timestamp has expired.
     *
     * @return A boolean
     */
    private boolean checkTimestamp(String ts) {
        if (timestampAgeLimit == 0) {
            return true;
        }

        if (ts == null) {
            return false;
        }

        long timestamp = Long.parseLong(ts, 10);
        long now = timeProvider.currentTimeMillis();
        return timestamp + timestampAgeLimit > now;
    }

    /**
     * Parse guacamole configuration xml.
     *
     * @return
     *     A Map of all configurations parsed from the config file.
     * @throws GuacamoleException 
     */
    public synchronized Map<String, GuacamoleConfiguration> parseConfigFile() 
            throws GuacamoleException {

        // Get configuration file
        File configFile = new File(environment.getGuacamoleHome(), DEFAULT_HMAC_CONFIG);
        
        if(!configFile.exists()) {
            logger.debug("Configuration file not found: \"{}\".", configFile);
            //return null;
        }

        logger.debug("Reading configuration file: \"{}\"", configFile);

        // Parse document
        try {
            // Set up parser
            HmacConfigurationHandler contentHandler = new HmacConfigurationHandler();

            XMLReader parser = XMLReaderFactory.createXMLReader();
            parser.setContentHandler(contentHandler);

            // Read and parse file
            Reader reader = new BufferedReader(new FileReader(configFile));
            parser.parse(new InputSource(reader));
            reader.close();
            
            Map<String, GuacamoleConfiguration> configs = null;
            configs = contentHandler.getConfigs();
            
            return configs;
        }
        catch (IOException e) {
            throw new GuacamoleServerException("Error reading configuration file " + DEFAULT_HMAC_CONFIG, e);
        }
        catch (SAXException e) {
            throw new GuacamoleServerException("Error parsing XML file " + DEFAULT_HMAC_CONFIG, e);
        }

    }

    /**
     * Given a user who has already been authenticated, returns a Map
     * containing all configurations for which that user is authorized.
     *
     * @param authenticatedUser
     *     The user whose authorized configurations are to be retrieved.
     *
     * @return
     *     A Map of all configurations authorized for use by the given user, or
     *     null if the user is not authorized to use any configurations.
     *
     * @throws GuacamoleException
     *     If an error occurs while retrieving configurations.
     */
    private Map<String, GuacamoleConfiguration> getAuthorizedConfigurationsForUser(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        // Pull cached configurations, if any
        if (authenticatedUser instanceof HmacAuthenticatedUser && authenticatedUser.getAuthenticationProvider() == this) {
            return ((HmacAuthenticatedUser) authenticatedUser).getAuthorizedConfigurations();
        }
        
        // Otherwise, pull using credentials
        return getAuthorizedConfigurations(authenticatedUser.getCredentials());

    }

    @Override
    public String getIdentifier() {
        return "hmac-auth-config";
    }

    @Override
    public AuthenticatedUser authenticateUser(final Credentials credentials)
            throws GuacamoleException {

        logger.debug("Authentication attempt");

        // Get configurations
        Map<String, GuacamoleConfiguration> configs = getAuthorizedConfigurations(credentials);

        // Return as unauthorized if not authorized to retrieve configs
        if (configs == null) {
            logger.debug("Configs are null");
            return null;
        }

        return new HmacAuthenticatedUser(this, credentials, configs);

    }

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) 
            throws GuacamoleException {

        HttpServletRequest request = credentials.getRequest();

        if(request == null)
        {
            return null;
        }

        // Debug all HTTP_GET variables.
        //@SuppressWarnings("unchecked")
        Map<String, String[]> params = request.getParameterMap();

        for (String name : params.keySet()) {
            String value = request.getParameter(name);

            logger.debug("kv: {} = {}", name, value);
        }

        Map<String, GuacamoleConfiguration> configs = null;

        synchronized (this) {
            configs = parseConfigFile();
        }

        // If no mapping available, report as such
        if (configs == null) {
            throw new GuacamoleServerException("Configuration could not be read.");
        }

        String signature = request.getParameter(SIGNATURE_PARAM);
        logger.debug("Get hmac signature: {}", signature);
        if (signature == null) {
            return null;
        }

        String connection = request.getParameter(CONNECTION_PARAM);
        logger.debug("Get connection: {}", connection);
        if (connection == null) {
            return null;
        }

        String timestamp = request.getParameter(TIMESTAMP_PARAM);
        logger.debug("Timestamp Age Limit: {}", timestampAgeLimit);
        logger.debug("Check timestamp: {}", checkTimestamp(timestamp));
        if (!checkTimestamp(timestamp)) {
            return null;
        }

        GuacamoleConfiguration config = configs.get(connection);
        if(config == null) {
            return null;
        }

        String serverId = GuacamoleProperties.getRequiredProperty(HMAC_SERVER_ID);

        StringBuilder message = new StringBuilder(timestamp)
            .append(config.getProtocol())
            .append(serverId);

        for (String name : SIGNED_PARAMETERS) {
            String value = config.getParameter(name);
            if (value == null) {
                continue;
            }
            message.append(name);
            message.append(value);
        }

        logger.debug("Get hmac message: {}", message.toString());

        if (!signatureVerifier.verifySignature(signature, message.toString())) {
            return null;
        }

        // Only return the config for the requested connection        
        configs.clear();
        configs.put(connection, config);

        return configs;
    }

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        // Get configurations
        Map<String, GuacamoleConfiguration> configs = getAuthorizedConfigurationsForUser(authenticatedUser);

        // Return as unauthorized if not authorized to retrieve configs
        if (configs == null) {
            return null;
        }

        // Return user context restricted to authorized configs
        return new SimpleUserContext(this, authenticatedUser.getIdentifier(), configs);

    }

    @Override
    // Re-parse config xml for logged in user on each page refresh.
    public AuthenticatedUser updateAuthenticatedUser(AuthenticatedUser authenticatedUser, Credentials credentials) 
            throws GuacamoleException {
    
        // Get configurations
        Map<String, GuacamoleConfiguration> configs = getAuthorizedConfigurations(credentials);

        // Return as unauthorized if not authorized to retrieve configs
        if (configs == null) {
            return null;
        }

        return new HmacAuthenticatedUser(this, credentials, configs);
    }

    @Override
    // Create new user context with new config.
    public UserContext updateUserContext(UserContext context, AuthenticatedUser authenticatedUser) 
            throws GuacamoleException {
                        
        // Get configurations
        Map<String, GuacamoleConfiguration> configs = getAuthorizedConfigurationsForUser(authenticatedUser);
        
        // Return as unauthorized if not authorized to retrieve configs
        if (configs == null) {
            return null;
        }

        // Return user context restricted to authorized configs
        return new SimpleUserContext(this, authenticatedUser.getIdentifier(), configs);
    }
}
