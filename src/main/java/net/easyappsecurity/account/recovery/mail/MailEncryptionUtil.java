package net.easyappsecurity.account.recovery.mail;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.mail.Address;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;

public class MailEncryptionUtil {

    private static final String SIGNING_JKS = "easyappsec.jks";
    private static final String SECRET_KEY = "op3n.cod3z";

    public static MimeMessage encryptMessage(MimeMessage message, byte[] recipientCerttificate) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        X509Certificate recipientCert = getRecipientPublicCertificate(recipientCerttificate);

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));

        MimeBodyPart msg = new MimeBodyPart();
        msg.setContent(message.getContent(), message.getContentType());

        MimeBodyPart mp = gen.generate(msg,
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC)
                        .setProvider("BC")
                        .build()
        );
        message.setContent(mp.getContent(), mp.getContentType());
        message.saveChanges();

        return message;
    }


    public static MimeMessage signMessage(MimeMessage message) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        CertificateDetails certDetails = CertificateUtil.getCertificateDetails(SIGNING_JKS, SECRET_KEY);

        SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
        capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
        capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
        capabilities.addCapability(SMIMECapability.dES_CBC);
        capabilities.addCapability(SMIMECapability.aES256_CBC);

        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new SMIMECapabilitiesAttribute(capabilities));

        IssuerAndSerialNumber issAndSer = new IssuerAndSerialNumber(
                new X500Name(
                        certDetails.getX509Certificate().getIssuerDN().getName()),
                certDetails.getX509Certificate().getSerialNumber()
        );
        attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(issAndSer));

        SMIMESignedGenerator signer = new SMIMESignedGenerator();

        signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider("BC")
                .setSignedAttributeGenerator(new AttributeTable(attributes))
                .build("SHA1withRSA", certDetails.getPrivateKey(),
                        certDetails.getX509Certificate()));

        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        certList.add(certDetails.getX509Certificate());

        JcaCertStore bcerts = new JcaCertStore(certList);
        signer.addCertificates(bcerts);

        MimeMultipart mm = signer.generate(message);

        message.setContent(mm, mm.getContentType());
        message.saveChanges();

        return message;
    }

    private static X509Certificate getRecipientPublicCertificate(byte[] recipientCerttificate) throws Exception {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream certificateInputStream = new ByteArrayInputStream(recipientCerttificate);
        X509Certificate recipientCert = (X509Certificate) fact.generateCertificate(certificateInputStream);
        return recipientCert;
    }

}
