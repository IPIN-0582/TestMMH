package com.example.digital_signature_demo.service;

import com.example.digital_signature_demo.model.Document;
import com.example.digital_signature_demo.repository.DocumentRepository;
import net.thiim.dilithium.impl.Dilithium;
import net.thiim.dilithium.impl.DilithiumPrivateKeyImpl;
import net.thiim.dilithium.impl.DilithiumPublicKeyImpl;
import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
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
            // Tạo cặp khóa sử dụng thuật toán Dilithium với thông số LEVEL2
            DilithiumParameterSpec spec = DilithiumParameterSpec.LEVEL2;
            byte[] seed = new byte[32];
            new SecureRandom().nextBytes(seed);
            KeyPair keyPair = Dilithium.generateKeyPair(spec, seed);

            // Lấy khóa riêng và khóa công khai
            DilithiumPrivateKeyImpl privateKey = (DilithiumPrivateKeyImpl) keyPair.getPrivate();
            DilithiumPublicKeyImpl publicKey = (DilithiumPublicKeyImpl) keyPair.getPublic();

            // Ký tài liệu
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

    public boolean verifyDocument(Long documentId, byte[] documentContent) {
        try {
            Document document = documentRepository.findById(documentId)
                    .orElseThrow(() -> new RuntimeException("Document not found"));

            byte[] signature = document.getSignature();
            byte[] publicKeyBytes = Base64.getDecoder().decode(document.getPublicKey());

            // Tạo lại đối tượng DilithiumPublicKeyImpl với các tham số đúng
            DilithiumParameterSpec spec = DilithiumParameterSpec.LEVEL2;
            byte[] rho = new byte[32]; // Giá trị này cần được xác định từ khóa công khai hoặc bằng cách khác
            PolyVec t1 = new PolyVec(spec.k); // Giá trị này cũng cần được xác định hoặc tính toán
            byte[] pubbytes = publicKeyBytes;
            PolyVec[] A = new PolyVec[spec.l]; // Giá trị này cũng cần được xác định hoặc tính toán

             DilithiumPublicKeyImpl publicKey = new DilithiumPublicKeyImpl(spec, rho, t1, pubbytes, A);

            return Dilithium.verify(publicKey, signature, documentContent);
        } catch (Exception e) {
            logger.error("Error verifying document", e);
            throw new RuntimeException("Error verifying document", e);
        }
    }
}
