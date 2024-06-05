package  com.example.digital_signature_demo.service;

import  com.example.digital_signature_demo.model.Document;
import  com.example.digital_signature_demo.repository.DocumentRepository;
import net.thiim.dilithium.impl.Dilithium;
import net.thiim.dilithium.impl.DilithiumPrivateKeyImpl;
import net.thiim.dilithium.impl.DilithiumPublicKeyImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class DocumentService {

    private static final Logger logger = LoggerFactory.getLogger(DocumentService.class);

    @Autowired
    private DocumentRepository documentRepository;

    public String signDocument(byte[] documentContent) {
        try {
            // Tạo cặp khóa sử dụng thuật toán Dilithium
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Dilithium");
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Lấy khóa riêng và khóa công khai
            DilithiumPrivateKeyImpl privateKey = (DilithiumPrivateKeyImpl) keyPair.getPrivate();
            DilithiumPublicKeyImpl publicKey = (DilithiumPublicKeyImpl) keyPair.getPublic();

            // Ký tài liệu
            Dilithium dilithium = new Dilithium();
            byte[] signature = Dilithium.sign(privateKey, documentContent);
            String publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String privateKeyEncoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());

            // Lưu tài liệu đã ký và khóa công khai vào cơ sở dữ liệu
            Document document = new Document();
            document.setSignature(signature);
            document.setPublicKey(publicKeyEncoded);
            documentRepository.save(document);

            return privateKeyEncoded;
        } catch (Exception e) {
            logger.error("Error signing document", e);
            throw new RuntimeException("Error signing document", e);
        }
    }
}
