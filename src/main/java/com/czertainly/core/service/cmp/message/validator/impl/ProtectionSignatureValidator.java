package com.czertainly.core.service.cmp.message.validator.impl;

import com.czertainly.core.api.cmp.error.CmpConfigurationException;
import com.czertainly.core.api.cmp.error.CmpBaseException;
import com.czertainly.core.api.cmp.error.CmpProcessingException;
import com.czertainly.core.api.cmp.error.ImplFailureInfo;
import com.czertainly.core.service.cmp.message.ConfigurationContext;
import com.czertainly.core.service.cmp.message.PkiMessageDumper;
import com.czertainly.core.service.cmp.message.validator.Validator;
import com.czertainly.core.service.cmp.util.CryptoUtil;
import com.czertainly.core.service.cmp.util.CertUtil;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;


/**
 * <h6>Signature validator</h6>
 * <p>
 * In this case, the sender possesses a signature key pair and simply
 * signs the PKI message.  <code>PKIProtection</code> will contain the signature
 * value and the <code>protectionAlg</code> will be an <code>AlgorithmIdentifier</code> for a
 * digital signature (e.g., md5WithRSAEncryption or dsaWithSha-1).
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3">PKI Message Protection</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.3">Signature</a>
 */
class ProtectionSignatureValidator implements Validator<PKIMessage, Void> {

    private static final Logger LOG = LoggerFactory.getLogger(ProtectionSignatureValidator.class.getName());

    /**
     * Signature-base protection implementation assumes:
     *  <ul>
     *      <ol>that incoming message has <code>extraCert</code> field NOT EMPTY.</ol>
     *      <ol>try to find first certificate from <code>extraCert</code></ol>
     *      <ol>try to get public key of first certificate from <code>extraCert</code></ol>
     *      <ol>given public key is used for signature verification</ol>
     *      <ol>subject of signature {@link ProtectedPart} is count from {@link PKIHeader} and {@link PKIBody} values</ol>
     *      <ol>given counted {@link ProtectedPart} is verify against value in {@link PKIMessage#getProtection()}</ol>
     *  </ul>
     *
     * @param message is subject of signature-based validation
     * @return null, if validation is ok
     *
     * @throws CmpProcessingException if validation has failed
     */
    @Override
    public Void validate(PKIMessage message, ConfigurationContext configuration) throws CmpBaseException {
        ASN1OctetString tid = message.getHeader().getTransactionID();
        String msgType = PkiMessageDumper.msgTypeAsString(message.getBody().getType());
        CMPCertificate[] extraCerts = message.getExtraCerts();
        if (extraCerts == null || extraCerts.length == 0 || extraCerts[0] == null) {
            LOG.error("TID={}, TP={}, PN={} | extraCerts are empty", tid, msgType, configuration.getName());
            throw new CmpProcessingException(PKIFailureInfo.addInfoNotAvailable,
                    ImplFailureInfo.CRYPTOSIG541);
        }

        try {
            List<X509Certificate> extraCertsAsX509 = CertUtil.toX509Certificates(extraCerts);
            PKIHeader header = message.getHeader();
            byte[] protectedBytes = new ProtectedPart(header, message.getBody()).getEncoded(ASN1Encoding.DER);
            byte[] protectionBytes = message.getProtection().getBytes();
            X509Certificate singerCertificate = extraCertsAsX509.get(0);
            LOG.info("CERT, sn={}", singerCertificate.getSerialNumber().toString(16));
            Signature signature = Signature.getInstance(
                    header.getProtectionAlg().getAlgorithm().getId(),
                    CryptoUtil.getBouncyCastleProvider());
            signature.initVerify(extraCertsAsX509.get(0).getPublicKey());
            signature.update(protectedBytes);
            if (!signature.verify(protectionBytes, 0, protectionBytes.length)) {
                throw new CmpProcessingException(PKIFailureInfo.wrongIntegrity,
                        ImplFailureInfo.CRYPTOSIG542);
            }

            FileOutputStream keyfos = new FileOutputStream("toceczr.cert");
            keyfos.write(extraCertsAsX509.get(0).getEncoded());
            keyfos.close();
        } catch(CmpProcessingException ex) {
            throw ex;
        }  catch (final KeyException | NoSuchAlgorithmException ex) {
            throw new CmpProcessingException(PKIFailureInfo.badAlg,
                    ImplFailureInfo.CRYPTOSIG543);
        } catch(Exception ex) {
            throw new CmpProcessingException(
                    PKIFailureInfo.notAuthorized,
                    ex.getClass().getSimpleName() + ":" + ex.getLocalizedMessage());
        }
        return null;
    }
}
