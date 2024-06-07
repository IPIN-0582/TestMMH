package com.example.digital_signature_demo.service;

import org.apache.pdfbox.text.PDFTextStripperByArea;
import org.apache.pdfbox.text.TextPosition;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;

import java.awt.Rectangle;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

public class CustomPDFTextStripperByArea extends PDFTextStripperByArea {

    private List<TextPosition> textPositions;

    public CustomPDFTextStripperByArea() throws IOException {
        super();
        textPositions = new ArrayList<>();
    }

    @Override
    protected void processTextPosition(TextPosition text) {
        super.processTextPosition(text);
        textPositions.add(text);
    }

    public TextPosition getLastTextPosition(PDDocument document, int pageIndex) throws IOException {
        PDPage page = document.getPage(pageIndex);
        Rectangle rect = new Rectangle(0, 0, (int) page.getMediaBox().getWidth(), (int) page.getMediaBox().getHeight());
        this.addRegion("region", rect);
        this.extractRegions(page);

        if (textPositions.isEmpty()) {
            return null;
        }
        return textPositions.get(textPositions.size() - 1);
    }
}
