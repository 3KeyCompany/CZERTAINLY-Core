package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.acme.AcmeAccountListResponseDto;
import com.czertainly.api.model.client.acme.AcmeAccountResponseDto;
import com.czertainly.api.model.core.acme.AccountStatus;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.Client;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.acme.AcmeAccount;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.repository.AcmeProfileRepository;
import com.czertainly.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.ClientRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.dao.repository.acme.AcmeAccountRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.security.cert.CertificateException;
import java.util.List;

@SpringBootTest
@Transactional
@Rollback
@WithMockUser(roles="SUPERADMINISTRATOR")
public class AcmeAccountServiceTest {

    private static final String ADMIN_NAME = "ACME_USER";

    private static final String RA_PROFILE_NAME = "testRaProfile1";
    private static final String CLIENT_NAME = "testClient1";

    @Autowired
    private RaProfileService raProfileService;

    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ClientRepository clientRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;

    private RaProfile raProfile;
    private Certificate certificate;
    private CertificateContent certificateContent;
    private Client client;
    private AuthorityInstanceReference authorityInstanceReference;
    private Connector connector;

    @Autowired
    private AcmeAccountService acmeAccountService;

    @Autowired
    private AcmeAccountRepository acmeAccountRepository;

    @Autowired
    private AcmeProfileService acmeProfileService;

    @Autowired
    private AcmeProfileRepository acmeProfileRepository;

    private AcmeProfile acmeProfile;

    private AcmeAccount acmeAccount;

    @BeforeEach
    public void setUp() {

        certificateContent = new CertificateContent();
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setSerialNumber("123456789");
        certificate = certificateRepository.save(certificate);

        client = new Client();
        client.setName(CLIENT_NAME);
        client.setCertificate(certificate);
        client.setSerialNumber(certificate.getSerialNumber());
        client = clientRepository.save(client);

        connector = new Connector();
        connector.setUrl("http://localhost:3665");
        connector = connectorRepository.save(connector);

        authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        raProfile = new RaProfile();
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);

        acmeProfile = new AcmeProfile();
        acmeProfile.setWebsite("sample website");
        acmeProfile.setTermsOfServiceUrl("sample terms");
        acmeProfile.setValidity(30);
        acmeProfile.setRetryInterval(30);
        acmeProfile.setDescription("sample description");
        acmeProfile.setName("sameName");
        acmeProfile.setDnsResolverPort("53");
        acmeProfile.setDnsResolverIp("localhost");
        acmeProfile.setTermsOfServiceChangeUrl("change url");
        acmeProfile.setUuid("1757e43e-7d12-11ec-90d6-0242ac120003");
        acmeProfileRepository.save(acmeProfile);


        acmeAccount = new AcmeAccount();
        acmeAccount.setUuid("1757e43e-7d12-11ec-90d6-0242ac120004");
        acmeAccount.setStatus(AccountStatus.VALID);
        acmeAccount.setEnabled(true);
        acmeAccount.setAccountId("D65fAtrgfAD");
        acmeAccount.setTermsOfServiceAgreed(true);
        acmeAccount.setAcmeProfile(acmeProfile);
        acmeAccount.setRaProfile(raProfile);
        acmeAccountRepository.save(acmeAccount);
    }

    @Test
    public void testListAdmins() {
        List<AcmeAccountListResponseDto> accounts = acmeAccountService.listAcmeAccounts();
        Assertions.assertNotNull(accounts);
        Assertions.assertFalse(accounts.isEmpty());
        Assertions.assertEquals(1, accounts.size());
        Assertions.assertEquals(acmeAccount.getAccountId(), accounts.get(0).getAccountId());
    }

    @Test
    public void testGetAdminById() throws NotFoundException {
        AcmeAccountResponseDto dto = acmeAccountService.getAcmeAccount(acmeAccount.getUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(acmeAccount.getAccountId(), dto.getAccountId());
        Assertions.assertNotNull(acmeAccount.getId());
    }

    @Test
    public void testGetAdminById_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeAccountService.getAcmeAccount("wrong-uuid"));
    }

    @Test
    public void testRemoveAdmin() throws NotFoundException {
        acmeAccountService.revokeAccount(acmeAccount.getUuid());
        Assertions.assertEquals(AccountStatus.REVOKED, acmeAccountService.getAcmeAccount(acmeAccount.getUuid()).getStatus());
    }

    @Test
    public void testRemoveAdmin_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeAccountService.getAcmeAccount("some-id"));
    }

    @Test
    public void testEnableAdmin() throws NotFoundException, CertificateException {
        acmeAccountService.enableAccount(acmeAccount.getUuid());
        Assertions.assertEquals(true, acmeAccountService.getAcmeAccount(acmeAccount.getUuid()).isEnabled());
    }

    @Test
    public void testEnableAdmin_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeAccountService.enableAccount("wrong-uuid"));
    }

    @Test
    public void testDisableAdmin() throws NotFoundException {
        acmeAccountService.disableAccount(acmeAccount.getUuid());
        Assertions.assertEquals(false, acmeAccountService.getAcmeAccount(acmeAccount.getUuid()).isEnabled());
    }

    @Test
    public void testDisableAdmin_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeAccountService.disableAccount("wrong-uuid"));
    }

    @Test
    public void testBulkRemove() throws NotFoundException {
        acmeAccountService.bulkRevokeAccount(List.of(acmeAccount.getUuid()));
        Assertions.assertEquals(AccountStatus.REVOKED ,acmeAccountService.getAcmeAccount(acmeAccount.getUuid()).getStatus());
    }

    @Test
    public void testBulkEnable() throws NotFoundException {
        acmeAccountService.bulkEnableAccount(List.of(acmeAccount.getUuid()));
        Assertions.assertEquals(true, acmeAccountService.getAcmeAccount(acmeAccount.getUuid()).isEnabled());
    }

    @Test
    public void testBulkDisable() throws NotFoundException {
        acmeAccountService.bulkDisableAccount(List.of(acmeAccount.getUuid()));
        Assertions.assertEquals(false, acmeAccountService.getAcmeAccount(acmeAccount.getUuid()).isEnabled());
    }
}
