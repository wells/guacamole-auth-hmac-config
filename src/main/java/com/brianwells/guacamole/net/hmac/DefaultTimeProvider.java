package com.brianwells.guacamole.net.hmac;

public class DefaultTimeProvider implements TimeProviderInterface {
    public long currentTimeMillis() {
        return System.currentTimeMillis();
    }
}
