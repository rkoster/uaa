package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.SpringServletXmlFiltersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.OverridingClassLoader;

import java.lang.reflect.InvocationTargetException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientCertificateMapperAvailabilityTest {
    private static final String MAPPER = "org.cloudfoundry.router.jakarta.ClientCertificateMapper";

    @Test
    void disabledFeatureDoesNotLoadMissingMapper() throws Exception {
        MapperUnavailableClassLoader loader = new MapperUnavailableClassLoader();
        Object config = loader.loadClass(SpringServletXmlFiltersConfiguration.class.getName())
                .getConstructor().newInstance();

        FilterRegistrationBean<?> registration = (FilterRegistrationBean<?>) config.getClass()
                .getMethod("clientCertificateMapperFilter", boolean.class).invoke(config, false);

        assertThat(registration.isEnabled()).isFalse();
        assertThat(loader.mapperLoadAttempted).isFalse();
    }

    @Test
    void enabledFeatureFailsWhenMapperIsMissing() throws Exception {
        MapperUnavailableClassLoader loader = new MapperUnavailableClassLoader();
        Object config = loader.loadClass(SpringServletXmlFiltersConfiguration.class.getName())
                .getConstructor().newInstance();

        assertThatThrownBy(() -> config.getClass().getMethod("clientCertificateMapperFilter", boolean.class)
                .invoke(config, true))
                .isInstanceOf(InvocationTargetException.class)
                .cause().isInstanceOf(IllegalStateException.class)
                .hasMessage("Failed to instantiate ClientCertificateMapper")
                .hasCauseInstanceOf(ClassNotFoundException.class);
        assertThat(loader.mapperLoadAttempted).isTrue();
    }

    // Reload only the factory so its Class.forName uses this loader. All other application and
    // Spring types retain their normal identity; the mapper is deliberately unavailable.
    private static class MapperUnavailableClassLoader extends OverridingClassLoader {
        private boolean mapperLoadAttempted;

        MapperUnavailableClassLoader() {
            super(SpringServletXmlFiltersConfiguration.class.getClassLoader());
        }

        @Override
        protected boolean isEligibleForOverriding(String className) {
            return className.equals(SpringServletXmlFiltersConfiguration.class.getName());
        }

        @Override
        public Class<?> loadClass(String name) throws ClassNotFoundException {
            if (MAPPER.equals(name)) {
                mapperLoadAttempted = true;
                throw new ClassNotFoundException(name);
            }
            return super.loadClass(name);
        }
    }
}
