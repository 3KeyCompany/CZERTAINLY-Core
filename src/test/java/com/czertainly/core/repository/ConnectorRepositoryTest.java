package com.czertainly.core.repository;

import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.repository.ConnectorRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@SpringBootTest
@Transactional
@Rollback
public class ConnectorRepositoryTest {

    @Autowired
    private ConnectorRepository connectorRepository;

    @Test
    public void testCreateConnector() {
        Connector request = new Connector();
        request.setName("testConnector");
        request.setUrl("testUrl");
        request.setFunctionGroups(Collections.emptySet());

        Connector result = connectorRepository.save(request);
        Assertions.assertNotNull(result.getId());
        Assertions.assertNotNull(result.getUuid());
    }
}
