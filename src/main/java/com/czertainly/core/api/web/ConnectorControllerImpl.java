package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.core.web.ConnectorController;
import com.czertainly.api.model.client.connector.ConnectDto;
import com.czertainly.api.model.client.connector.ConnectRequestDto;
import com.czertainly.api.model.client.connector.ConnectorRequestDto;
import com.czertainly.api.model.client.connector.ConnectorUpdateRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.HealthDto;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.common.attribute.AttributeDefinition;
import com.czertainly.api.model.common.attribute.RequestAttributeDto;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.model.auth.ActionName;
import com.czertainly.core.model.auth.ResourceName;
import com.czertainly.core.service.ConnectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Map;

@RestController
public class ConnectorControllerImpl implements ConnectorController {

    @Autowired
    private ConnectorService connectorService;

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.LIST,isListingEndPoint = true)
    public List<ConnectorDto> listConnectors() {
        return connectorService.listConnectors();
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.LIST, isListingEndPoint = true)
    public List<ConnectorDto> listConnectors(
            @RequestParam FunctionGroupCode functionGroup,
            @RequestParam String kind) throws NotFoundException {
        return connectorService.listConnectors(functionGroup, kind);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.LIST, isListingEndPoint = true)
    public List<ConnectorDto> listConnectorsByFunctionGroup(
            @RequestParam FunctionGroupCode functionGroup) throws NotFoundException {
        return connectorService.listConnectorsByFunctionGroup(functionGroup);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.APPROVE)
    public void bulkApprove(List<String> uuids) throws NotFoundException, ValidationException {
        connectorService.approve(uuids);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.RECONNECT)
    public void bulkReconnect(List<String> uuids) throws ValidationException, NotFoundException, ConnectorException {
        connectorService.reconnect(uuids);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.DETAIL)
    public ConnectorDto getConnector(@PathVariable String uuid) throws NotFoundException, ConnectorException {
        return connectorService.getConnector(uuid);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.CREATE)
    public ResponseEntity<?> createConnector(@RequestBody ConnectorRequestDto request)
            throws AlreadyExistException, ConnectorException {
        ConnectorDto connectorDto = connectorService.createConnector(request);

        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{uuid}")
                .buildAndExpand(connectorDto.getUuid()).toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(connectorDto.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.UPDATE)
    public ConnectorDto editConnector(@PathVariable String uuid, @RequestBody ConnectorUpdateRequestDto request)
            throws ConnectorException {
        return connectorService.editConnector(uuid, request);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.DELETE)
    public void deleteConnector(@PathVariable String uuid) throws NotFoundException {
        connectorService.deleteConnector(uuid);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.CONNECT)
    public List<ConnectDto> connect(@RequestBody ConnectRequestDto request) throws ValidationException, ConnectorException {
        return connectorService.connect(request);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.RECONNECT)
    public List<ConnectDto> reconnect(@PathVariable String uuid) throws ValidationException, NotFoundException, ConnectorException {
        return connectorService.reconnect(uuid);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.APPROVE)
    public void approve(@PathVariable String uuid) throws NotFoundException, ValidationException {
        connectorService.approve(uuid);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.CHECK_HEALTH)
    public HealthDto checkHealth(@PathVariable String uuid) throws NotFoundException, ValidationException, ConnectorException {
        return connectorService.checkHealth(uuid);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.LIST_ATTRIBUTES)
    public List<AttributeDefinition> getAttributes(@PathVariable String uuid,
                                                   @PathVariable String functionGroup,
                                                   @PathVariable String kind) throws NotFoundException, ConnectorException {
        return connectorService.getAttributes(uuid, FunctionGroupCode.findByCode(functionGroup), kind);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.VALIDATE_ATTRIBUTES)
    public void validateAttributes(@PathVariable String uuid,
                                      @PathVariable String functionGroup,
                                      @PathVariable String kind,
                                      @RequestBody List<RequestAttributeDto> attributes)
            throws NotFoundException, ConnectorException {
        connectorService.validateAttributes(uuid, FunctionGroupCode.findByCode(functionGroup), attributes,
                kind);
    }

	@Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.LIST_ATTRIBUTES)
	public Map<FunctionGroupCode, Map<String, List<AttributeDefinition>>> getAttributesAll(String uuid) throws NotFoundException, ConnectorException {
		return connectorService.getAllAttributesOfConnector(uuid);
	}

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.DELETE)
    public List<BulkActionMessageDto> bulkDeleteConnector(List<String> uuids) throws NotFoundException, ValidationException, ConnectorException {
        return connectorService.bulkDeleteConnector(uuids);
    }

    @Override
    @AuthEndpoint(resourceName = ResourceName.CONNECTOR, actionName = ActionName.FORCE_DELETE)
    public List<BulkActionMessageDto> forceDeleteConnector(List<String> uuids) throws NotFoundException, ValidationException {
        return connectorService.forceDeleteConnector(uuids);
    }
}
