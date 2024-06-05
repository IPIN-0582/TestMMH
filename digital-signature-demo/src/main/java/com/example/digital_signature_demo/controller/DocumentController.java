package com.example.digital_signature_demo.controller;

import  com.example.digital_signature_demo.service.DocumentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {
    @Autowired
    private DocumentService documentService;

    @PostMapping("/sign")
    public String signDocument(@RequestParam("file") MultipartFile file) throws IOException {
        byte[] documentContent = file.getBytes();
        return documentService.signDocument(documentContent);
    }

    @PostMapping("/verify")
    public String verifyDocument(@RequestParam("documentId") Long documentId, @RequestParam("file") MultipartFile file) throws IOException {
        byte[] documentContent = file.getBytes();
        boolean isVerified = documentService.verifyDocument(documentId, documentContent);
        return isVerified ? "Document is verified and not tampered with." : "Document is tampered with or invalid.";
    }
}