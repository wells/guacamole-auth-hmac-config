package com.brianwells.guacamole.net.hmac;

import java.util.Map;
import java.util.UUID;
import org.glyptodon.guacamole.net.auth.AbstractAuthenticatedUser;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;

/**
 * AuthenticatedUser which contains its own predefined set of authorized
 * configurations.
 */
public class HmacAuthenticatedUser extends AbstractAuthenticatedUser {

    /**
     * The credentials provided when this AuthenticatedUser was
     * authenticated.
     */
    private final Credentials credentials;

    /**
     * The authentication provider this AuthenticatedUser was authenticated with.
     */
    private final AuthenticationProvider authenticationProvider;

    /**
     * The GuacamoleConfigurations that this AuthenticatedUser is
     * authorized to use.
     */
    private Map<String, GuacamoleConfiguration> configs;

    /**
     * Creates a new SimpleAuthenticatedUser associated with the given
     * credentials and having access to the given Map of
     * GuacamoleConfigurations.
     *
     * @param credentials
     *     The credentials provided by the user when they authenticated.
     *
     * @param configs
     *     A Map of all GuacamoleConfigurations for which this user has
     *     access. The keys of this Map are Strings which uniquely identify
     *     each configuration.
     */
    public HmacAuthenticatedUser(AuthenticationProvider authenticationProvider, Credentials credentials, Map<String, GuacamoleConfiguration> configs) {

        // Store provider credentials and configurations
        this.authenticationProvider = authenticationProvider;
        this.credentials = credentials;
        this.configs = configs;

        // Pull username from credentials if it exists
        String username = credentials.getUsername();
        if (username != null && !username.isEmpty()) {
            setIdentifier(username);

        // Otherwise generate a random username
        } else {
            setIdentifier(UUID.randomUUID().toString());
        }

    }

    /**
     * Returns a Map containing all GuacamoleConfigurations that this user
     * is authorized to use. The keys of this Map are Strings which
     * uniquely identify each configuration.
     *
     * @return
     *     A Map of all configurations for which this user is authorized.
     */
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations() {
        return configs;
    }
    
    public void setAuthorizedConfigurations(Map<String, GuacamoleConfiguration> configs) {
        this.configs = configs;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authenticationProvider;
    }

    @Override
    public Credentials getCredentials() {
        return credentials;
    }
}
