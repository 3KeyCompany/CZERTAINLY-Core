package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.DiscoveryController;
import com.czertainly.api.model.client.discovery.DiscoveryDto;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.core.discovery.DiscoveryHistoryDto;
import com.czertainly.core.dao.entity.DiscoveryHistory;
import com.czertainly.core.service.DiscoveryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
public class DiscoveryControllerImpl implements DiscoveryController {

	@Autowired
	private DiscoveryService discoveryService;

	@Override
	public List<DiscoveryHistoryDto> listDiscovery() {
		return discoveryService.listDiscovery();
	}

	@Override
	public DiscoveryHistoryDto getDiscovery(@PathVariable String uuid) throws NotFoundException {
		return discoveryService.getDiscovery(uuid);
	}

	@Override
	public ResponseEntity<?> createDiscovery(@RequestBody DiscoveryDto request)
            throws NotFoundException, ConnectorException, AlreadyExistException {
		DiscoveryHistory modal = discoveryService.createDiscoveryModal(request);
		discoveryService.createDiscovery(request, modal);
		URI location = ServletUriComponentsBuilder
				.fromCurrentRequest()
				.path("/{uuid}")
				.buildAndExpand(modal.getUuid())
				.toUri();
		UuidDto dto = new UuidDto();
		dto.setUuid(modal.getUuid());
		return ResponseEntity.created(location).body(dto);
	}

	@Override
	public void removeDiscovery(@PathVariable String uuid) throws NotFoundException {
		discoveryService.removeDiscovery(uuid);
	}

	@Override
	public void bulkRemoveDiscovery(List<String> discoveryUuids) throws NotFoundException {
		discoveryService.bulkRemoveDiscovery(discoveryUuids);
	}
}
