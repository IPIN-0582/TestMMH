package com.example.digital_signature_demo.controller;

import com.example.digital_signature_demo.service.DocumentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/documents")
public class DocumentController {

    @Autowired
    private DocumentService documentService;

    @PostMapping("/sign")
    public ResponseEntity<byte[]> signDocument(@RequestParam("file") MultipartFile file) {
        try {
            byte[] documentContent = file.getBytes();
            byte[] signedDocument = documentService.signDocument(documentContent);

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed_document.pdf");
            headers.add(HttpHeaders.CONTENT_TYPE, "application/pdf");

            return new ResponseEntity<>(signedDocument, headers, HttpStatus.OK);
        } catch (IOException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyDocument(@RequestParam("file") MultipartFile file) {
        try {
            byte[] documentContent = file.getBytes();
            boolean isValid = documentService.verifyDocument(documentContent);

            if (isValid) {
                return new ResponseEntity<>("Document is valid", HttpStatus.OK);
            } else {
                return new ResponseEntity<>("Document is invalid", HttpStatus.BAD_REQUEST);
            }
        } catch (IOException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
