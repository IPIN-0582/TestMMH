package com.example.digital_signature_demo.service;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.digital_signature_demo.model.Document;
import com.example.digital_signature_demo.repository.DocumentRepository;
import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.provider.DilithiumProvider;
import net.thiim.dilithium.impl.PackingUtils;
import net.thiim.dilithium.impl.Dilithium;
import net.thiim.dilithium.interfaces.DilithiumPrivateKey;
import net.thiim.dilithium.interfaces.DilithiumPublicKey;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Optional;
import java.util.Map;
import java.util.HashMap;

import javax.imageio.ImageIO;

@Service
public class DocumentService {

    private static final Logger logger = LoggerFactory.getLogger(DocumentService.class);

    @Autowired
    private DocumentRepository documentRepository;

    static {
        // Đăng ký DilithiumProvider
        Security.addProvider(new DilithiumProvider());
    }

    public byte[] signDocument(byte[] documentContent) {
        try {
            // Tạo cặp khóa
            SecureRandom random = new SecureRandom();
            byte[] seed = new byte[32]; // Kích thước hạt giống là 32 bytes
            random.nextBytes(seed);
            DilithiumParameterSpec params = DilithiumParameterSpec.LEVEL3; // Sử dụng thông số LEVEL3
            KeyPair keyPair = Dilithium.generateKeyPair(params, seed);

            // Lưu thông tin tài liệu tạm thời vào cơ sở dữ liệu để lấy ID
            Document document = new Document();
            document.setPublicKey(keyPair.getPublic().getEncoded());
            documentRepository.save(document);

            // Tạo nội dung cho mã QR chứa documentId
            String qrContent = "Document ID: " + document.getId();

            // Tạo mã QR
            ByteArrayOutputStream qrOutputStream = new ByteArrayOutputStream();
            generateQRCodeImage(qrContent, 100, 100, qrOutputStream); // Tăng kích thước mã QR để đảm bảo rõ ràng
            byte[] qrImage = qrOutputStream.toByteArray();

            // Tạo tệp PDF với mã QR
            PDDocument pdfDocument = PDDocument.load(documentContent);
            PDPage lastPage = pdfDocument.getPage(pdfDocument.getNumberOfPages() - 1);
            PDPageContentStream contentStream = new PDPageContentStream(pdfDocument, lastPage, PDPageContentStream.AppendMode.APPEND, true, true);

            // Viết mã QR vào trang cuối của tài liệu PDF
            PDImageXObject pdImage = PDImageXObject.createFromByteArray(pdfDocument, qrImage, "QR");
            contentStream.drawImage(pdImage, 50, 70, 100, 100); // Đặt mã QR tại vị trí dễ nhận dạng hơn
            contentStream.close();

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            pdfDocument.save(outputStream);
            pdfDocument.close();

            byte[] pdfWithQR = outputStream.toByteArray();

            // Ký lại tài liệu PDF với mã QR
            DilithiumPrivateKey privateKey = (DilithiumPrivateKey) keyPair.getPrivate();
            byte[] signature = Dilithium.sign(privateKey, pdfWithQR);

            // Cập nhật chữ ký trong cơ sở dữ liệu
            document.setSignature(signature);
            documentRepository.save(document);

            return pdfWithQR;
        } catch (Exception e) {
            logger.error("Lỗi khi ký tài liệu", e);
            throw new RuntimeException("Lỗi khi ký tài liệu", e);
        }
    }

    public boolean verifyDocument(byte[] signedDocumentContent) {
        try {
            // Đọc nội dung PDF và mã QR để lấy documentId
            PDDocument pdfDocument = PDDocument.load(signedDocumentContent);
            String qrContent = extractQRCodeContentFromLastPage(pdfDocument);
            pdfDocument.close();

            // Phân tích nội dung QR
            String documentIdStr = qrContent.split(": ")[1];
            Long documentId = Long.parseLong(documentIdStr);

            // Lấy tài liệu từ cơ sở dữ liệu
            Document document = documentRepository.findById(documentId)
                    .orElseThrow(() -> new RuntimeException("Không tìm thấy tài liệu"));

            // Giải mã khóa công khai
            byte[] publicKeyBytes = document.getPublicKey();
            DilithiumPublicKey publicKey = (DilithiumPublicKey) PackingUtils.unpackPublicKey(DilithiumParameterSpec.LEVEL3, publicKeyBytes);

            // Xác thực nội dung tài liệu đã ký
            boolean isVerified = Dilithium.verify(publicKey, document.getSignature(), signedDocumentContent);
            if (isVerified) {
                logger.info("Tài liệu được xác thực thành công.");
            } else {
                logger.warn("Xác thực tài liệu thất bại.");
            }
            return isVerified;
        } catch (Exception e) {
            logger.error("Lỗi khi xác thực tài liệu", e);
            throw new RuntimeException("Lỗi khi xác thực tài liệu", e);
        }
    }

    private void generateQRCodeImage(String text, int width, int height, ByteArrayOutputStream outputStream) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height, hints);
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
    }

    private String extractQRCodeContentFromLastPage(PDDocument document) throws IOException, NotFoundException {
        int lastPageIndex = document.getNumberOfPages() - 1;
        PDFRenderer pdfRenderer = new PDFRenderer(document);
        BufferedImage bim = pdfRenderer.renderImageWithDPI(lastPageIndex, 300, ImageType.RGB); // Nâng cao độ phân giải để tăng độ rõ ràng

        LuminanceSource source = new BufferedImageLuminanceSource(bim);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        Result result = new MultiFormatReader().decode(bitmap);

        return result.getText();
    }
}
